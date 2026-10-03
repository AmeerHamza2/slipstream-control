/** Payload of POST /internal/v1/entitlements (docs/CONTRACT.md). */
export type EntitlementSource = 'stripe' | 'app_store' | 'google_play';
export type EntitlementStatus = 'active' | 'grace' | 'expired' | 'revoked' | 'refunded';

export interface EntitlementEvent {
  event_id: string;
  source: EntitlementSource;
  user_id: string;
  product_id: string;
  status: EntitlementStatus;
  expires_at: string;
  original_transaction_id: string;
  occurred_at: string;
}

/**
 * Result of mapping a store notification: either an event to forward, or a reason to
 * acknowledge without forwarding (unhandled type, unattributable purchase, ...).
 */
export type MapResult = { kind: 'event'; event: EntitlementEvent } | { kind: 'ignore'; reason: string };

export const ignore = (reason: string): MapResult => ({ kind: 'ignore', reason });

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const isUuid = (v: unknown): v is string => typeof v === 'string' && UUID_RE.test(v);

/** RFC 3339 UTC, second precision (matches the rest of the platform). */
export function iso(d: Date | number): string {
  const date = typeof d === 'number' ? new Date(d) : d;
  return date.toISOString().replace(/\.\d{3}Z$/, 'Z');
}
