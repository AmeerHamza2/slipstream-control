import type { FastifyInstance } from 'fastify';
import { badRequest, forbidden } from '../errors.js';
import { type RouteDeps, webhookAck } from '../http.js';
import { AppleVerificationError } from './jws.js';
import {
  eventFromAppleTransaction,
  mapAppleNotification,
  type AppleNotificationPayload,
  type AppleRenewalInfo,
  type AppleTransaction,
} from './mapping.js';

export function registerAppleRoutes(app: FastifyInstance, deps: RouteDeps): void {
  const verify = async <T>(jws: unknown, what: string): Promise<T> => {
    if (typeof jws !== 'string' || jws.length > 64 * 1024) throw badRequest(`${what} missing`);
    try {
      return await deps.apple.verify<T>(jws);
    } catch (err) {
      if (err instanceof AppleVerificationError) throw badRequest(`${what} failed verification: ${err.message}`);
      throw err;
    }
  };
  const checkBundle = (bundleId: string | undefined) => {
    if (deps.appleBundleId && bundleId !== deps.appleBundleId) throw badRequest('bundle id mismatch');
  };

  // App Store Server Notifications v2.
  app.post('/billing/apple/notifications', async (req) => {
    const body = req.body as { signedPayload?: unknown } | undefined;
    const n = await verify<AppleNotificationPayload>(body?.signedPayload, 'signedPayload');
    if (typeof n.notificationUUID !== 'string' || typeof n.notificationType !== 'string' || typeof n.signedDate !== 'number') {
      throw badRequest('notification payload incomplete');
    }
    checkBundle(n.data?.bundleId);

    // The nested JWS are signed independently and must pass the same chain checks.
    const tx = n.data?.signedTransactionInfo
      ? await verify<AppleTransaction>(n.data.signedTransactionInfo, 'signedTransactionInfo')
      : undefined;
    const renewal = n.data?.signedRenewalInfo
      ? await verify<AppleRenewalInfo>(n.data.signedRenewalInfo, 'signedRenewalInfo')
      : undefined;
    if (tx) checkBundle(tx.bundleId);

    const mapped = mapAppleNotification(n, tx, renewal);
    const ctx = { event_id: n.notificationUUID, type: n.notificationType, subtype: n.subtype };
    if (mapped.kind === 'ignore') {
      req.log.info({ ...ctx, reason: mapped.reason }, 'apple notification ignored');
      return webhookAck({ ignored: mapped.reason });
    }
    return webhookAck(await deps.pipeline.process(mapped.event, req.log));
  });

  // Client-submitted StoreKit 2 transaction (Transaction.jwsRepresentation).
  app.post('/billing/apple/verify', async (req) => {
    const userId = await deps.users.verify(req.headers.authorization);
    const body = req.body as { signed_transaction?: unknown } | undefined;
    const tx = await verify<AppleTransaction>(body?.signed_transaction, 'signed_transaction');
    checkBundle(tx.bundleId);
    if (typeof tx.transactionId !== 'string' || typeof tx.originalTransactionId !== 'string' || typeof tx.signedDate !== 'number') {
      throw badRequest('transaction payload incomplete');
    }
    // Binding: the app sets appAccountToken = our user id at purchase time, so a
    // transaction bought by one account cannot be replayed to unlock another.
    if (tx.appAccountToken?.toLowerCase() !== userId.toLowerCase()) {
      req.log.warn({ user_id: userId }, 'apple transaction bound to a different account');
      throw forbidden('transaction belongs to a different account');
    }

    const event = eventFromAppleTransaction(tx, userId, deps.now());
    const outcome = await deps.pipeline.process(event, req.log);
    return {
      status: event.status,
      expires_at: event.expires_at,
      applied: outcome.outcome === 'forwarded' ? outcome.result.applied : false,
    };
  });
}
