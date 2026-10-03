import { createHash, timingSafeEqual } from 'node:crypto';
import type { FastifyBaseLogger, FastifyInstance } from 'fastify';
import { iso, isUuid, type EntitlementEvent } from '../entitlement.js';
import { badRequest, HttpError, forbidden, unauthorized, upstream } from '../errors.js';
import { type RouteDeps, webhookAck } from '../http.js';
import { GooglePlayUnavailableError, type SubscriptionPurchaseV2 } from './client.js';
import { expiresAt, googleStatusFor, resolveDerived, statusFromPurchase, tokenId } from './mapping.js';

interface PubSubPush {
  message?: { data?: string; messageId?: string; message_id?: string };
  subscription?: string;
}
interface DeveloperNotification {
  packageName?: string;
  eventTimeMillis?: string;
  subscriptionNotification?: { notificationType?: number; purchaseToken?: string; subscriptionId?: string };
  voidedPurchaseNotification?: { purchaseToken?: string; productType?: number };
  testNotification?: object;
}

const VOIDED_PRODUCT_TYPE_SUBSCRIPTION = 1;

/** Constant-time comparison that also hides the expected length (compare digests). */
export function safeEqual(a: string, b: string): boolean {
  const ha = createHash('sha256').update(a).digest();
  const hb = createHash('sha256').update(b).digest();
  return timingSafeEqual(ha, hb);
}

export function registerGoogleRoutes(app: FastifyInstance, deps: RouteDeps): void {
  const lookup = async (pkg: string, token: string): Promise<SubscriptionPurchaseV2 | null> => {
    try {
      return await deps.google.getSubscription(pkg, token);
    } catch (err) {
      if (err instanceof GooglePlayUnavailableError) throw upstream(503, 'Google Play lookup failed; retry later');
      throw err;
    }
  };

  const acknowledgeIfPending = async (
    log: FastifyBaseLogger, pkg: string, productId: string, token: string, p: SubscriptionPurchaseV2,
  ) => {
    if (p.acknowledgementState !== 'ACKNOWLEDGEMENT_STATE_PENDING') return;
    try {
      await deps.google.acknowledge(pkg, productId, token);
    } catch (err) {
      // Not fatal: the next RTDN / verify call retries; Google allows 3 days.
      log.warn({ err: (err as Error).message }, 'google acknowledge failed');
    }
  };

  // Pub/Sub push of Real-Time Developer Notifications.
  app.post('/billing/google/rtdn', async (req) => {
    const auth = req.headers.authorization ?? '';
    if (!auth.startsWith('Bearer ') || !safeEqual(auth.slice(7), deps.googlePushToken)) {
      throw unauthorized('invalid push token');
    }

    const push = req.body as PubSubPush | undefined;
    const messageId = push?.message?.messageId ?? push?.message?.message_id;
    if (typeof messageId !== 'string' || typeof push?.message?.data !== 'string') {
      throw badRequest('not a Pub/Sub push message');
    }
    let n: DeveloperNotification;
    try {
      n = JSON.parse(Buffer.from(push.message.data, 'base64').toString('utf8')) as DeveloperNotification;
    } catch {
      // Poison message: acknowledge so Pub/Sub stops redelivering it.
      req.log.error({ event_id: messageId }, 'RTDN data is not JSON');
      return webhookAck({ ignored: 'undecodable data' });
    }
    const ack = (reason: string) => {
      req.log.info({ event_id: messageId, reason }, 'google notification ignored');
      return webhookAck({ ignored: reason });
    };

    if (n.testNotification) return ack('test notification');
    const pkg = n.packageName;
    if (!pkg) return ack('no packageName');
    if (deps.googlePackageName && pkg !== deps.googlePackageName) return ack('package not ours');

    const eventTime = Number(n.eventTimeMillis);
    const occurredMs = Number.isFinite(eventTime) && eventTime > 0 ? eventTime : deps.now();

    let token: string | undefined;
    let mapping: ReturnType<typeof googleStatusFor>;
    let productHint: string | undefined;
    if (n.subscriptionNotification) {
      token = n.subscriptionNotification.purchaseToken;
      mapping = googleStatusFor(Number(n.subscriptionNotification.notificationType));
      productHint = n.subscriptionNotification.subscriptionId;
      if (!mapping) return ack(`notification type ${n.subscriptionNotification.notificationType} not handled`);
    } else if (n.voidedPurchaseNotification?.productType === VOIDED_PRODUCT_TYPE_SUBSCRIPTION) {
      token = n.voidedPurchaseNotification.purchaseToken;
      mapping = 'refunded';
    } else {
      return ack('not a subscription notification');
    }
    if (!token) return ack('no purchase token');

    const purchase = await lookup(pkg, token);
    if (!purchase) return ack('purchase token unknown to Google');
    const userId = purchase.externalAccountIdentifiers?.obfuscatedExternalAccountId;
    if (!isUuid(userId)) return ack('purchase has no obfuscatedExternalAccountId');

    const status = resolveDerived(mapping, purchase, deps.now());
    const productId = productHint ?? purchase.lineItems?.[0]?.productId ?? 'unknown';
    const event: EntitlementEvent = {
      event_id: messageId,
      source: 'google_play',
      user_id: userId,
      product_id: productId,
      status,
      expires_at: status === 'revoked' || status === 'refunded' ? iso(occurredMs) : expiresAt(purchase, occurredMs),
      original_transaction_id: tokenId(token),
      occurred_at: iso(occurredMs),
    };
    const outcome = await deps.pipeline.process(event, req.log);
    if (status === 'active') await acknowledgeIfPending(req.log, pkg, productId, token, purchase);
    return webhookAck(outcome);
  });

  // Client-submitted purchase token right after BillingClient reports a purchase.
  app.post('/billing/google/verify', async (req) => {
    const userId = await deps.users.verify(req.headers.authorization);
    const body = req.body as { purchase_token?: unknown; product_id?: unknown } | undefined;
    const token = body?.purchase_token;
    const productId = body?.product_id;
    if (typeof token !== 'string' || token.length === 0 || token.length > 4096) throw badRequest('purchase_token required');
    if (typeof productId !== 'string' || !/^[a-z0-9._]{1,150}$/i.test(productId)) throw badRequest('product_id required');
    const pkg = deps.googlePackageName;
    if (!pkg) throw upstream(503, 'Google Play not configured');

    const purchase = await lookup(pkg, token);
    if (!purchase) throw badRequest('unknown purchase token');
    if (!purchase.lineItems?.some((li) => li.productId === productId)) throw badRequest('product_id does not match purchase');
    if (purchase.externalAccountIdentifiers?.obfuscatedExternalAccountId?.toLowerCase() !== userId.toLowerCase()) {
      req.log.warn({ user_id: userId }, 'google purchase bound to a different account');
      throw forbidden('purchase belongs to a different account');
    }

    const now = deps.now();
    const status = statusFromPurchase(purchase, now);
    if (!status) throw new HttpError(402, 'payment_required', 'purchase is pending');
    const expires = expiresAt(purchase, now);
    const event: EntitlementEvent = {
      // Same token + same state = same event; a renewal (new expiry) is a new one.
      event_id: `google_play:${tokenId(token)}:${status}:${expires}`,
      source: 'google_play',
      user_id: userId,
      product_id: productId,
      status,
      expires_at: expires,
      original_transaction_id: tokenId(token),
      occurred_at: iso(now),
    };
    const outcome = await deps.pipeline.process(event, req.log);
    if (status === 'active') await acknowledgeIfPending(req.log, pkg, productId, token, purchase);
    return {
      status,
      expires_at: expires,
      applied: outcome.outcome === 'forwarded' ? outcome.result.applied : false,
    };
  });
}
