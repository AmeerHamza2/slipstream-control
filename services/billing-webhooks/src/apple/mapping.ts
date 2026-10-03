import { ignore, iso, isUuid, type EntitlementEvent, type EntitlementStatus, type MapResult } from '../entitlement.js';

/** Decoded App Store Server Notification v2 (`responseBodyV2DecodedPayload`). */
export interface AppleNotificationPayload {
  notificationType: string;
  subtype?: string;
  notificationUUID: string;
  signedDate: number;
  data?: {
    bundleId?: string;
    environment?: string;
    signedTransactionInfo?: string;
    signedRenewalInfo?: string;
  };
}

/** Decoded `JWSTransactionDecodedPayload` (fields we use). */
export interface AppleTransaction {
  transactionId: string;
  originalTransactionId: string;
  productId: string;
  bundleId?: string;
  purchaseDate?: number;
  expiresDate?: number;
  signedDate: number;
  appAccountToken?: string;
  revocationDate?: number;
  revocationReason?: number;
}

/** Decoded `JWSRenewalInfoDecodedPayload` (fields we use). */
export interface AppleRenewalInfo {
  gracePeriodExpiresDate?: number;
}

/**
 * notificationType (+ subtype) -> status. Types not listed are acknowledged and ignored
 * (DID_CHANGE_RENEWAL_STATUS, PRICE_INCREASE, TEST, ...): they do not change access.
 */
export function appleStatusFor(type: string): EntitlementStatus | undefined {
  switch (type) {
    case 'SUBSCRIBED': // INITIAL_BUY / RESUBSCRIBE
    case 'DID_RENEW': // incl. subtype BILLING_RECOVERY
    case 'OFFER_REDEEMED':
      return 'active';
    case 'DID_FAIL_TO_RENEW': // subtype GRACE_PERIOD, or none = billing retry
      return 'grace';
    case 'EXPIRED':
    case 'GRACE_PERIOD_EXPIRED':
      return 'expired';
    case 'REFUND':
      return 'refunded';
    case 'REVOKE': // Family Sharing access withdrawn
      return 'revoked';
    default:
      return undefined;
  }
}

export function mapAppleNotification(
  n: AppleNotificationPayload,
  tx: AppleTransaction | undefined,
  renewal: AppleRenewalInfo | undefined,
): MapResult {
  const status = appleStatusFor(n.notificationType);
  if (!status) return ignore(`notification ${n.notificationType} not handled`);
  if (!tx) return ignore('notification without transaction info');
  if (!isUuid(tx.appAccountToken)) return ignore('transaction has no appAccountToken');

  let expiresMs: number;
  switch (status) {
    case 'grace':
      // Grace period: access until Apple's grace end. Billing retry without a grace
      // period: expiresDate is already past, so the api treats it as inactive.
      expiresMs = renewal?.gracePeriodExpiresDate ?? tx.expiresDate ?? n.signedDate;
      break;
    case 'refunded':
    case 'revoked':
      expiresMs = tx.revocationDate ?? n.signedDate;
      break;
    default:
      expiresMs = tx.expiresDate ?? n.signedDate;
  }

  return {
    kind: 'event',
    event: {
      event_id: n.notificationUUID,
      source: 'app_store',
      user_id: tx.appAccountToken,
      product_id: tx.productId,
      status,
      expires_at: iso(expiresMs),
      original_transaction_id: tx.originalTransactionId,
      occurred_at: iso(n.signedDate),
    },
  };
}

/**
 * Client-submitted transaction (POST /billing/apple/verify). There is no notification
 * UUID, so the event id is derived from the transaction and the resulting status: the
 * same JWS submitted twice is a duplicate, a later refund of it is not.
 */
export function eventFromAppleTransaction(tx: AppleTransaction, userId: string, now: number): EntitlementEvent {
  let status: EntitlementStatus;
  let expiresMs: number;
  if (tx.revocationDate !== undefined) {
    status = tx.revocationReason !== undefined ? 'refunded' : 'revoked';
    expiresMs = tx.revocationDate;
  } else {
    expiresMs = tx.expiresDate ?? tx.signedDate;
    status = expiresMs > now ? 'active' : 'expired';
  }
  return {
    event_id: `app_store:${tx.transactionId}:${status}`,
    source: 'app_store',
    user_id: userId,
    product_id: tx.productId,
    status,
    expires_at: iso(expiresMs),
    original_transaction_id: tx.originalTransactionId,
    occurred_at: iso(tx.signedDate),
  };
}
