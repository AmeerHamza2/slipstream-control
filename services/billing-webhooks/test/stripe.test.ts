import assert from 'node:assert/strict';
import { after, before, beforeEach, describe, it } from 'node:test';
import { mapStripeEvent, PROVISIONAL_SECONDS, type StripeEvent } from '../src/stripe/mapping.js';
import { StripeSignatureError, stripeSignatureHeader, verifyStripeSignature } from '../src/stripe/signature.js';
import { forwarded, setup, STRIPE_SECRET, USER, type TestContext } from './helpers/app.js';

const NOW = 1_790_000_000;
const body = Buffer.from('{"id":"evt_1","type":"ping"}');

describe('Stripe signature', () => {
  it('accepts a valid signature', () => {
    verifyStripeSignature(body, stripeSignatureHeader(body, STRIPE_SECRET, NOW), STRIPE_SECRET, NOW);
  });

  it('rejects a tampered body, wrong secret, missing or malformed header', () => {
    const h = stripeSignatureHeader(body, STRIPE_SECRET, NOW);
    const bad: Array<[Buffer, string | undefined, string]> = [
      [Buffer.from('{"id":"evt_2"}'), h, STRIPE_SECRET],
      [body, h, 'whsec_other'],
      [body, undefined, STRIPE_SECRET],
      [body, 'garbage', STRIPE_SECRET],
      [body, `t=${NOW}`, STRIPE_SECRET],
      [body, h.replace(/v1=/, 'v0='), STRIPE_SECRET],
    ];
    for (const [b, header, secret] of bad) {
      assert.throws(() => verifyStripeSignature(b, header, secret, NOW), StripeSignatureError);
    }
  });

  it('enforces the 300 s tolerance in both directions', () => {
    const old = stripeSignatureHeader(body, STRIPE_SECRET, NOW - 301);
    const future = stripeSignatureHeader(body, STRIPE_SECRET, NOW + 301);
    assert.throws(() => verifyStripeSignature(body, old, STRIPE_SECRET, NOW), /tolerance/);
    assert.throws(() => verifyStripeSignature(body, future, STRIPE_SECRET, NOW), /tolerance/);
    verifyStripeSignature(body, stripeSignatureHeader(body, STRIPE_SECRET, NOW - 300), STRIPE_SECRET, NOW);
  });

  it('accepts any matching v1 among several (secret rotation)', () => {
    const good = stripeSignatureHeader(body, STRIPE_SECRET, NOW).split(',')[1]!;
    const other = stripeSignatureHeader(body, 'whsec_old', NOW).split(',')[1]!;
    verifyStripeSignature(body, `t=${NOW},${other},${good},v0=abc`, STRIPE_SECRET, NOW);
    assert.throws(() => verifyStripeSignature(body, `t=${NOW},${other}`, STRIPE_SECRET, NOW));
  });
});

const ev = (type: string, object: unknown, id = 'evt_1'): StripeEvent => ({ id, type, created: NOW, data: { object } });
const sub = (status: string, extra: Record<string, unknown> = {}) => ({
  object: 'subscription', id: 'sub_123', status, metadata: { user_id: USER },
  items: { data: [{ current_period_end: NOW + 30 * 86400, price: { id: 'price_1', lookup_key: 'premium_monthly' } }] },
  ...extra,
});
const iso = (s: number) => new Date(s * 1000).toISOString().replace('.000Z', 'Z');

describe('Stripe event mapping', () => {
  it('checkout.session.completed uses the expanded subscription period end', () => {
    const r = mapStripeEvent(ev('checkout.session.completed', { mode: 'subscription', client_reference_id: USER, subscription: sub('active') }));
    assert.equal(r.kind, 'event');
    assert.deepEqual(r.kind === 'event' && r.event, {
      event_id: 'evt_1', source: 'stripe', user_id: USER, product_id: 'premium_monthly', status: 'active',
      expires_at: iso(NOW + 30 * 86400), original_transaction_id: 'sub_123', occurred_at: iso(NOW),
    });
  });

  it('checkout.session.completed without expansion gets a provisional window', () => {
    const r = mapStripeEvent(ev('checkout.session.completed', { mode: 'subscription', metadata: { user_id: USER }, subscription: 'sub_9' }));
    assert.ok(r.kind === 'event');
    assert.equal(r.event.expires_at, iso(NOW + PROVISIONAL_SECONDS));
    assert.equal(r.event.original_transaction_id, 'sub_9');
  });

  const table: Array<[string, string, string]> = [
    ['customer.subscription.updated', 'active', 'active'],
    ['customer.subscription.updated', 'trialing', 'active'],
    ['customer.subscription.updated', 'past_due', 'grace'],
    ['customer.subscription.updated', 'canceled', 'expired'],
    ['customer.subscription.updated', 'unpaid', 'expired'],
    ['customer.subscription.deleted', 'canceled', 'expired'],
  ];
  for (const [type, stripeStatus, expected] of table) {
    it(`${type} (${stripeStatus}) -> ${expected}`, () => {
      const r = mapStripeEvent(ev(type, sub(stripeStatus)));
      assert.ok(r.kind === 'event');
      assert.equal(r.event.status, expected);
      assert.equal(r.event.user_id, USER);
      assert.equal(r.event.original_transaction_id, 'sub_123');
    });
  }

  it('reads the legacy top-level current_period_end and ended_at', () => {
    const r = mapStripeEvent(ev('customer.subscription.deleted', { id: 'sub_1', status: 'canceled', metadata: { user_id: USER }, ended_at: NOW - 5 }));
    assert.ok(r.kind === 'event');
    assert.equal(r.event.expires_at, iso(NOW - 5));
  });

  it('invoice.payment_failed -> grace until the next retry (both API shapes)', () => {
    const legacy = mapStripeEvent(ev('invoice.payment_failed', {
      subscription: 'sub_123', subscription_details: { metadata: { user_id: USER } }, next_payment_attempt: NOW + 3 * 86400,
    }));
    const basil = mapStripeEvent(ev('invoice.payment_failed', {
      parent: { subscription_details: { subscription: 'sub_123', metadata: { user_id: USER } } }, next_payment_attempt: null,
    }));
    assert.ok(legacy.kind === 'event' && basil.kind === 'event');
    assert.equal(legacy.event.status, 'grace');
    assert.equal(legacy.event.expires_at, iso(NOW + 3 * 86400));
    assert.equal(basil.event.expires_at, iso(NOW)); // no retries left: grace already over
  });

  it('ignores unhandled types, incomplete subscriptions and events without a user', () => {
    assert.equal(mapStripeEvent(ev('invoice.paid', {})).kind, 'ignore');
    assert.equal(mapStripeEvent(ev('customer.subscription.updated', sub('incomplete'))).kind, 'ignore');
    assert.equal(mapStripeEvent(ev('customer.subscription.updated', { ...sub('active'), metadata: {} })).kind, 'ignore');
    assert.equal(mapStripeEvent(ev('checkout.session.completed', { mode: 'payment', client_reference_id: USER })).kind, 'ignore');
  });
});

describe('POST /billing/stripe/webhook', () => {
  let ctx: TestContext;
  before(async () => (ctx = await setup()));
  after(() => ctx.close());
  beforeEach(() => {
    ctx.api.received.length = 0;
    ctx.api.script.length = 0;
  });

  const deliver = (event: StripeEvent, sig?: string) => {
    const payload = JSON.stringify(event);
    return ctx.app.inject({
      method: 'POST', url: '/billing/stripe/webhook', payload,
      headers: {
        'content-type': 'application/json; charset=utf-8',
        'stripe-signature': sig ?? stripeSignatureHeader(payload, STRIPE_SECRET, Math.floor(Date.now() / 1000)),
      },
    });
  };

  it('verifies, maps, forwards (signed) and acknowledges', async () => {
    const res = await deliver(ev('customer.subscription.updated', sub('active'), 'evt_route_1'));
    assert.equal(res.statusCode, 200);
    assert.deepEqual(res.json(), { received: true, applied: true });
    assert.equal(ctx.api.received.length, 1);
    assert.equal(ctx.api.received[0]!.signatureValid, true);
    assert.equal(forwarded(ctx.api)[0]!.event_id, 'evt_route_1');
  });

  it('rejects a bad signature without forwarding', async () => {
    const res = await deliver(ev('customer.subscription.updated', sub('active'), 'evt_bad'), `t=${Math.floor(Date.now() / 1000)},v1=${'0'.repeat(64)}`);
    assert.equal(res.statusCode, 400);
    assert.equal(res.json().error.code, 'invalid_request');
    assert.equal(ctx.api.received.length, 0);
  });

  it('short-circuits a redelivery after a successful forward', async () => {
    const e = ev('customer.subscription.updated', sub('past_due'), 'evt_dup');
    assert.equal((await deliver(e)).statusCode, 200);
    const again = await deliver(e);
    assert.equal(again.statusCode, 200);
    assert.deepEqual(again.json(), { received: true, duplicate: true });
    assert.equal(ctx.api.received.length, 1);
  });

  it('answers 503 + Retry-After when the api never accepts, and does not remember the event', async () => {
    ctx.api.script.push(500, 500, 500, 500, 500);
    const e = ev('customer.subscription.updated', sub('active'), 'evt_down');
    const res = await deliver(e);
    assert.equal(res.statusCode, 503);
    assert.equal(res.json().error.code, 'internal');
    assert.match(String(res.headers['retry-after']), /^\d+$/);
    assert.equal(ctx.api.received.length, 5);
    assert.equal(await ctx.store.isProcessed('evt_down'), false);
    // Stripe redelivers once the api is back.
    assert.equal((await deliver(e)).statusCode, 200);
    assert.equal(await ctx.store.isProcessed('evt_down'), true);
  });

  it('answers 502 when the api permanently rejects the event (4xx)', async () => {
    ctx.api.script.push(422);
    const res = await deliver(ev('customer.subscription.updated', sub('active'), 'evt_rej'));
    assert.equal(res.statusCode, 502);
    assert.equal(ctx.api.received.length, 1);
    assert.equal(await ctx.store.isProcessed('evt_rej'), false);
  });

  it('acknowledges ignorable events without forwarding', async () => {
    const res = await deliver(ev('charge.succeeded', {}, 'evt_ign'));
    assert.equal(res.statusCode, 200);
    assert.match(res.json().ignored, /not handled/);
    assert.equal(ctx.api.received.length, 0);
  });
});
