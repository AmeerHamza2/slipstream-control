import { ignore, iso, isUuid, type EntitlementStatus, type MapResult } from '../entitlement.js';

/**
 * Minimal shapes of the Stripe objects we read. Fields are optional because Stripe's
 * payload varies across API versions (e.g. `current_period_end` moved from the
 * subscription to its items in 2025-03-31, and `invoice.subscription` moved under
 * `invoice.parent.subscription_details`).
 */
interface StripePrice {
  id?: string;
  lookup_key?: string | null;
}
interface StripeSubscription {
  object?: 'subscription';
  id: string;
  status?: string;
  metadata?: Record<string, string>;
  current_period_end?: number;
  ended_at?: number | null;
  canceled_at?: number | null;
  items?: { data?: Array<{ current_period_end?: number; price?: StripePrice }> };
}
interface StripeCheckoutSession {
  client_reference_id?: string | null;
  mode?: string;
  subscription?: string | StripeSubscription | null;
  metadata?: Record<string, string>;
}
interface StripeInvoice {
  subscription?: string | null;
  subscription_details?: { metadata?: Record<string, string> } | null;
  parent?: { subscription_details?: { subscription?: string; metadata?: Record<string, string> } | null } | null;
  next_payment_attempt?: number | null;
  lines?: { data?: Array<{ price?: StripePrice }> };
}
export interface StripeEvent {
  id: string;
  type: string;
  created: number;
  data: { object: unknown };
}

/** Product used when Stripe gives us nothing better (no lookup_key / metadata). */
export const DEFAULT_PRODUCT_ID = 'premium_monthly';

/**
 * checkout.session.completed usually carries only the subscription *id*, so the period
 * end is unknown. We then grant a provisional window; the subscription/invoice events
 * that follow carry the authoritative period end.
 */
export const PROVISIONAL_SECONDS = 48 * 60 * 60;

export function mapStripeSubscriptionStatus(status: string | undefined): EntitlementStatus | undefined {
  switch (status) {
    case 'active':
    case 'trialing':
      return 'active';
    case 'past_due':
      return 'grace';
    case 'canceled':
    case 'unpaid':
    case 'incomplete_expired':
    case 'paused':
      return 'expired';
    default:
      return undefined; // incomplete: payment not yet confirmed, nothing to grant
  }
}

const periodEnd = (s: StripeSubscription): number | undefined =>
  s.current_period_end ?? s.items?.data?.[0]?.current_period_end;

const productOf = (s: StripeSubscription | undefined, metadata?: Record<string, string>): string => {
  const price = s?.items?.data?.[0]?.price;
  return metadata?.product_id || s?.metadata?.product_id || price?.lookup_key || price?.id || DEFAULT_PRODUCT_ID;
};

export function mapStripeEvent(event: StripeEvent): MapResult {
  const base = { event_id: event.id, source: 'stripe' as const, occurred_at: iso(event.created * 1000) };

  switch (event.type) {
    case 'checkout.session.completed': {
      const s = event.data.object as StripeCheckoutSession;
      if (s.mode && s.mode !== 'subscription') return ignore('checkout not in subscription mode');
      const sub = typeof s.subscription === 'object' && s.subscription ? s.subscription : undefined;
      const subId = typeof s.subscription === 'string' ? s.subscription : sub?.id;
      if (!subId) return ignore('checkout session without subscription');
      const userId = s.client_reference_id || s.metadata?.user_id || sub?.metadata?.user_id;
      if (!isUuid(userId)) return ignore('no user_id on checkout session');
      const end = (sub && periodEnd(sub)) ?? event.created + PROVISIONAL_SECONDS;
      return {
        kind: 'event',
        event: {
          ...base,
          user_id: userId,
          product_id: productOf(sub, s.metadata),
          status: 'active',
          expires_at: iso(end * 1000),
          original_transaction_id: subId,
        },
      };
    }

    case 'customer.subscription.updated':
    case 'customer.subscription.deleted': {
      const sub = event.data.object as StripeSubscription;
      const userId = sub.metadata?.user_id;
      if (!isUuid(userId)) return ignore('no metadata.user_id on subscription');
      const deleted = event.type === 'customer.subscription.deleted';
      const status = deleted ? 'expired' : mapStripeSubscriptionStatus(sub.status);
      if (!status) return ignore(`subscription status ${sub.status ?? 'unknown'} not mapped`);
      const end = deleted || status === 'expired'
        ? (sub.ended_at ?? sub.canceled_at ?? periodEnd(sub) ?? event.created)
        : (periodEnd(sub) ?? event.created);
      return {
        kind: 'event',
        event: {
          ...base,
          user_id: userId,
          product_id: productOf(sub),
          status,
          expires_at: iso(end * 1000),
          original_transaction_id: sub.id,
        },
      };
    }

    case 'invoice.payment_failed': {
      const inv = event.data.object as StripeInvoice;
      const subId = inv.subscription ?? inv.parent?.subscription_details?.subscription;
      if (!subId) return ignore('invoice not tied to a subscription');
      const userId = inv.subscription_details?.metadata?.user_id ?? inv.parent?.subscription_details?.metadata?.user_id;
      if (!isUuid(userId)) return ignore('no user_id on invoice subscription metadata');
      // Grace lasts until Stripe's next retry; with no retry left it is already over
      // (expires_at = now), and the api's "grace + future expiry" rule ends access.
      const end = inv.next_payment_attempt ?? event.created;
      const price = inv.lines?.data?.[0]?.price;
      return {
        kind: 'event',
        event: {
          ...base,
          user_id: userId,
          product_id: price?.lookup_key || price?.id || DEFAULT_PRODUCT_ID,
          status: 'grace',
          expires_at: iso(end * 1000),
          original_transaction_id: subId,
        },
      };
    }

    default:
      return ignore(`event type ${event.type} not handled`);
  }
}
