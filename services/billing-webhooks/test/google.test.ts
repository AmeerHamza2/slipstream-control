import assert from 'node:assert/strict';
import { after, before, beforeEach, describe, it } from 'node:test';
import type { SubscriptionPurchaseV2 } from '../src/google/client.js';
import { googleStatusFor, resolveDerived, statusFromPurchase, tokenId } from '../src/google/mapping.js';
import { forwarded, OTHER_USER, PACKAGE, PUSH_TOKEN, setup, USER, type TestContext } from './helpers/app.js';

const DAY = 86_400_000;
const now = Date.now();
const iso = (ms: number) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');

const purchase = (state: SubscriptionPurchaseV2['subscriptionState'], expiry: number, user = USER): SubscriptionPurchaseV2 => ({
  subscriptionState: state,
  lineItems: [{ productId: 'premium_monthly', expiryTime: new Date(expiry).toISOString() }],
  acknowledgementState: 'ACKNOWLEDGEMENT_STATE_PENDING',
  externalAccountIdentifiers: { obfuscatedExternalAccountId: user },
});

describe('Google RTDN mapping', () => {
  const table: Array<[number, string | undefined]> = [
    [4, 'active'], [2, 'active'], [1, 'active'], [7, 'active'], [6, 'grace'], [5, 'expired'],
    [13, 'expired'], [10, 'expired'], [12, 'revoked'], [3, 'derive'], [8, undefined], [11, undefined],
  ];
  for (const [type, status] of table) {
    it(`notificationType ${type} -> ${status ?? 'ignored'}`, () => assert.equal(googleStatusFor(type), status));
  }

  it('CANCELED keeps access until expiry', () => {
    assert.equal(resolveDerived('derive', purchase('SUBSCRIPTION_STATE_CANCELED', now + DAY), now), 'active');
    assert.equal(resolveDerived('derive', purchase('SUBSCRIPTION_STATE_CANCELED', now - DAY), now), 'expired');
  });

  it('purchase state mapping for client verify', () => {
    assert.equal(statusFromPurchase(purchase('SUBSCRIPTION_STATE_ACTIVE', now + DAY), now), 'active');
    assert.equal(statusFromPurchase(purchase('SUBSCRIPTION_STATE_IN_GRACE_PERIOD', now + DAY), now), 'grace');
    assert.equal(statusFromPurchase(purchase('SUBSCRIPTION_STATE_ON_HOLD', now - DAY), now), 'expired');
    assert.equal(statusFromPurchase(purchase('SUBSCRIPTION_STATE_PENDING', now + DAY), now), undefined);
  });
});

describe('Google routes', () => {
  let ctx: TestContext;
  before(async () => (ctx = await setup()));
  after(() => ctx.close());
  beforeEach(() => {
    ctx.api.received.length = 0;
    ctx.google.acknowledged.length = 0;
    ctx.google.down = false;
  });

  const rtdn = (messageId: string, notification: object, token = PUSH_TOKEN) =>
    ctx.app.inject({
      method: 'POST', url: '/billing/google/rtdn',
      headers: { authorization: `Bearer ${token}` },
      payload: {
        message: { data: Buffer.from(JSON.stringify(notification)).toString('base64'), messageId, publishTime: new Date().toISOString() },
        subscription: 'projects/p/subscriptions/rtdn',
      },
    });
  const subN = (type: number, purchaseToken: string) => ({
    version: '1.0', packageName: PACKAGE, eventTimeMillis: String(now),
    subscriptionNotification: { version: '1.0', notificationType: type, purchaseToken, subscriptionId: 'premium_monthly' },
  });

  it('rejects a wrong push token in constant time', async () => {
    const res = await rtdn('m0', subN(4, 'tok'), 'wrong');
    assert.equal(res.statusCode, 401);
    assert.equal(res.json().error.code, 'unauthorized');
  });

  it('SUBSCRIPTION_PURCHASED -> active from the purchase lookup, then acknowledges', async () => {
    ctx.google.purchases.set('tok-1', purchase('SUBSCRIPTION_STATE_ACTIVE', now + 30 * DAY));
    const res = await rtdn('msg-1', subN(4, 'tok-1'));
    assert.equal(res.statusCode, 200, res.body);
    assert.deepEqual(forwarded(ctx.api)[0], {
      event_id: 'msg-1', source: 'google_play', user_id: USER, product_id: 'premium_monthly', status: 'active',
      expires_at: iso(now + 30 * DAY), original_transaction_id: tokenId('tok-1'), occurred_at: iso(now),
    });
    assert.deepEqual(ctx.google.acknowledged, ['tok-1']);
    assert.ok(!ctx.api.received[0]!.body.includes('tok-1'), 'raw purchase token must not be forwarded');
  });

  it('CANCELED before expiry stays active; REVOKED is revoked', async () => {
    ctx.google.purchases.set('tok-2', purchase('SUBSCRIPTION_STATE_CANCELED', now + 5 * DAY));
    await rtdn('msg-2', subN(3, 'tok-2'));
    await rtdn('msg-3', subN(12, 'tok-2'));
    assert.deepEqual(forwarded(ctx.api).map((e) => e.status), ['active', 'revoked']);
  });

  it('answers 503 when Google is down so Pub/Sub redelivers', async () => {
    ctx.google.down = true;
    const res = await rtdn('msg-4', subN(2, 'tok-1'));
    assert.equal(res.statusCode, 503);
    assert.equal(ctx.api.received.length, 0);
  });

  it('acks test notifications, foreign packages and unknown tokens without forwarding', async () => {
    assert.equal((await rtdn('t1', { packageName: PACKAGE, testNotification: { version: '1.0' } })).statusCode, 200);
    assert.equal((await rtdn('t2', { ...subN(4, 'tok-1'), packageName: 'com.other' })).statusCode, 200);
    assert.equal((await rtdn('t3', subN(4, 'unknown'))).statusCode, 200);
    assert.equal(ctx.api.received.length, 0);
  });

  it('client verify: requires the JWT, product match and account binding', async () => {
    ctx.google.purchases.set('tok-v', purchase('SUBSCRIPTION_STATE_ACTIVE', now + 30 * DAY));
    const call = async (sub: string, body: object) =>
      ctx.app.inject({
        method: 'POST', url: '/billing/google/verify', payload: body,
        headers: { authorization: `Bearer ${await ctx.issuer.token(sub)}` },
      });

    const ok = await call(USER, { purchase_token: 'tok-v', product_id: 'premium_monthly' });
    assert.equal(ok.statusCode, 200, ok.body);
    assert.deepEqual(ok.json(), { status: 'active', expires_at: iso(now + 30 * DAY), applied: true });

    assert.equal((await call(OTHER_USER, { purchase_token: 'tok-v', product_id: 'premium_monthly' })).statusCode, 403);
    assert.equal((await call(USER, { purchase_token: 'tok-v', product_id: 'premium_yearly' })).statusCode, 400);
    assert.equal((await call(USER, { purchase_token: 'nope', product_id: 'premium_monthly' })).statusCode, 400);
    assert.equal(ctx.api.received.length, 1);
  });
});
