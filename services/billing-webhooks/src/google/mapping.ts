import { createHash } from 'node:crypto';
import { iso, type EntitlementStatus } from '../entitlement.js';
import type { SubscriptionPurchaseV2 } from './client.js';

/** RTDN `subscriptionNotification.notificationType` values (Play Developer API docs). */
export const GoogleNotificationType = {
  SUBSCRIPTION_RECOVERED: 1,
  SUBSCRIPTION_RENEWED: 2,
  SUBSCRIPTION_CANCELED: 3,
  SUBSCRIPTION_PURCHASED: 4,
  SUBSCRIPTION_ON_HOLD: 5,
  SUBSCRIPTION_IN_GRACE_PERIOD: 6,
  SUBSCRIPTION_RESTARTED: 7,
  SUBSCRIPTION_DEFERRED: 9,
  SUBSCRIPTION_PAUSED: 10,
  SUBSCRIPTION_REVOKED: 12,
  SUBSCRIPTION_EXPIRED: 13,
} as const;

/**
 * 'derive' = the notification alone does not determine access; use the purchase's
 * expiry (CANCELED: auto-renew turned off, access continues until expiryTime).
 */
export type GoogleMapping = EntitlementStatus | 'derive';

export function googleStatusFor(type: number): GoogleMapping | undefined {
  const T = GoogleNotificationType;
  switch (type) {
    case T.SUBSCRIPTION_PURCHASED:
    case T.SUBSCRIPTION_RENEWED:
    case T.SUBSCRIPTION_RECOVERED:
    case T.SUBSCRIPTION_RESTARTED:
      return 'active';
    case T.SUBSCRIPTION_IN_GRACE_PERIOD:
      return 'grace';
    case T.SUBSCRIPTION_ON_HOLD:
    case T.SUBSCRIPTION_PAUSED:
    case T.SUBSCRIPTION_EXPIRED:
      return 'expired';
    case T.SUBSCRIPTION_REVOKED:
      return 'revoked';
    case T.SUBSCRIPTION_CANCELED:
    case T.SUBSCRIPTION_DEFERRED:
      return 'derive';
    default:
      return undefined; // price change, pause schedule, ... : no access change
  }
}

/** Current status from the purchase resource itself (used by the client verify path). */
export function statusFromPurchase(p: SubscriptionPurchaseV2, now: number): EntitlementStatus | undefined {
  const expiry = expiryMs(p);
  switch (p.subscriptionState) {
    case 'SUBSCRIPTION_STATE_ACTIVE':
      return 'active';
    case 'SUBSCRIPTION_STATE_CANCELED':
      return expiry !== undefined && expiry > now ? 'active' : 'expired';
    case 'SUBSCRIPTION_STATE_IN_GRACE_PERIOD':
      return 'grace';
    case 'SUBSCRIPTION_STATE_ON_HOLD':
    case 'SUBSCRIPTION_STATE_PAUSED':
    case 'SUBSCRIPTION_STATE_EXPIRED':
      return 'expired';
    default:
      return undefined; // pending / unspecified: nothing to grant yet
  }
}

export function resolveDerived(mapping: GoogleMapping, p: SubscriptionPurchaseV2, now: number): EntitlementStatus {
  if (mapping !== 'derive') return mapping;
  const expiry = expiryMs(p);
  return expiry !== undefined && expiry > now ? 'active' : 'expired';
}

/** Latest expiry across line items (a subscription may hold several base plans). */
export function expiryMs(p: SubscriptionPurchaseV2): number | undefined {
  const times = (p.lineItems ?? [])
    .map((li) => (li.expiryTime ? Date.parse(li.expiryTime) : Number.NaN))
    .filter((t) => Number.isFinite(t));
  return times.length > 0 ? Math.max(...times) : undefined;
}

export function expiresAt(p: SubscriptionPurchaseV2, fallback: number): string {
  return iso(expiryMs(p) ?? fallback);
}

/**
 * Purchase tokens are bearer-like credentials and very long; we never log or forward
 * them raw. The api only needs a stable per-subscription id for ordering, so we send
 * a SHA-256 of the token (stable across renewals, which keep the same token).
 */
export const tokenId = (purchaseToken: string): string =>
  'gp_' + createHash('sha256').update(purchaseToken).digest('hex').slice(0, 40);
