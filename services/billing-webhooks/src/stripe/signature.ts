import { createHmac, timingSafeEqual } from 'node:crypto';

export const STRIPE_TOLERANCE_SECONDS = 300;

export class StripeSignatureError extends Error {}

/**
 * Verifies a `Stripe-Signature` header the way Stripe's SDKs do, without the SDK:
 *
 *   Stripe-Signature: t=1700000000,v1=<hex>,v1=<hex>,v0=<ignored>
 *
 * - expected = hex(HMAC_SHA256(secret, `${t}.${rawBody}`)) over the *raw* request bytes
 *   (re-serialised JSON would not match);
 * - any of the v1 values may match (several appear while a secret is being rolled);
 * - constant-time comparison;
 * - `t` must be within the tolerance of our clock (replay protection).
 */
export function verifyStripeSignature(
  rawBody: Buffer,
  header: string | undefined,
  secret: string,
  nowSeconds = Math.floor(Date.now() / 1000),
  toleranceSeconds = STRIPE_TOLERANCE_SECONDS,
): void {
  if (!header) throw new StripeSignatureError('missing Stripe-Signature header');

  let timestamp: number | undefined;
  const signatures: Buffer[] = [];
  for (const part of header.split(',')) {
    const idx = part.indexOf('=');
    if (idx < 0) continue;
    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (key === 't') timestamp = /^\d+$/.test(value) ? Number(value) : Number.NaN;
    else if (key === 'v1' && /^[0-9a-f]{64}$/i.test(value)) signatures.push(Buffer.from(value, 'hex'));
  }

  if (timestamp === undefined || !Number.isSafeInteger(timestamp)) {
    throw new StripeSignatureError('missing or invalid timestamp');
  }
  if (signatures.length === 0) throw new StripeSignatureError('no v1 signature');

  const expected = createHmac('sha256', secret)
    .update(`${timestamp}.`)
    .update(rawBody)
    .digest();

  // Compare against every candidate (no early exit) so timing reveals nothing.
  let matched = false;
  for (const sig of signatures) {
    if (timingSafeEqual(sig, expected)) matched = true;
  }
  if (!matched) throw new StripeSignatureError('signature mismatch');

  // Checked after the MAC so an attacker cannot probe our clock with unsigned requests.
  if (Math.abs(nowSeconds - timestamp) > toleranceSeconds) {
    throw new StripeSignatureError('timestamp outside tolerance');
  }
}

/** Test/helper: produce a header Stripe would send. */
export function stripeSignatureHeader(rawBody: string | Buffer, secret: string, t: number): string {
  const mac = createHmac('sha256', secret).update(`${t}.`).update(rawBody).digest('hex');
  return `t=${t},v1=${mac}`;
}
