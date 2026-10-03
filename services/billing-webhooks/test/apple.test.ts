import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { after, before, beforeEach, describe, it } from 'node:test';
import { extensionOids } from '../src/apple/der.js';
import { APPLE_RECEIPT_SIGNING_OID, AppleJwsVerifier, AppleVerificationError } from '../src/apple/jws.js';
import { appleStatusFor, mapAppleNotification, type AppleTransaction } from '../src/apple/mapping.js';
import { BUNDLE, forwarded, OTHER_USER, setup, USER, type TestContext } from './helpers/app.js';
import { makePki, makeRoot, type TestPki } from './helpers/certs.js';

const DAY = 86_400_000;
const now = Date.now();
const tx = (extra: Partial<AppleTransaction> = {}): AppleTransaction => ({
  transactionId: '2000000001', originalTransactionId: '2000000000', productId: 'com.slipstream.premium.monthly',
  bundleId: BUNDLE, purchaseDate: now - DAY, expiresDate: now + 30 * DAY, signedDate: now, appAccountToken: USER, ...extra,
});
const iso = (ms: number) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');

describe('Apple x5c chain + JWS verification', () => {
  let pki: TestPki;
  let verifier: AppleJwsVerifier;
  before(async () => {
    pki = await makePki();
    verifier = new AppleJwsVerifier({ rootCertificate: pki.root });
  });

  it('finds the receipt-signing OID in the generated leaf', () => {
    const leaf = Buffer.from(pki.x5c[0]!, 'base64');
    assert.ok(extensionOids(leaf).includes(APPLE_RECEIPT_SIGNING_OID));
  });

  it('accepts a correctly chained, correctly signed JWS (with or without the root in x5c)', async () => {
    assert.deepEqual(await verifier.verify(await pki.sign({ hello: 'world' })), { hello: 'world' });
    const twoCerts = await pki.sign({ a: 1 }, { x5c: pki.x5c.slice(0, 2) });
    assert.deepEqual(await verifier.verify(twoCerts), { a: 1 });
  });

  it('rejects a chain that leads to a different root', async () => {
    const otherRoot = await makeRoot('Evil Root');
    const evil = await makePki({}, otherRoot);
    await assert.rejects(verifier.verify(await evil.sign({ a: 1 })), /Apple root/);
    // ... even if the attacker appends the genuine root certificate
    const spliced = await evil.sign({ a: 1 }, { x5c: [evil.x5c[0]!, evil.x5c[1]!, pki.x5c[2]!] });
    await assert.rejects(verifier.verify(spliced), /chain signature invalid/);
  });

  it('rejects an expired leaf certificate', async () => {
    const expired = await makePki({ leafNotAfter: new Date(now - 1000) });
    const v = new AppleJwsVerifier({ rootCertificate: expired.root });
    await assert.rejects(v.verify(await expired.sign({ a: 1 })), /validity/);
  });

  it('rejects a JWS not signed by the leaf key', async () => {
    const { privateKey } = (await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])) as CryptoKeyPair;
    await assert.rejects(verifier.verify(await pki.sign({ a: 1 }, { key: privateKey })), /signature invalid/);
  });

  it('rejects a tampered payload', async () => {
    const [h, , s] = (await pki.sign({ amount: 1 })).split('.');
    const forged = `${h}.${Buffer.from(JSON.stringify({ amount: 1000 })).toString('base64url')}.${s}`;
    await assert.rejects(verifier.verify(forged), /signature invalid/);
  });

  it('rejects certificates without the Apple marker OIDs or a non-CA intermediate', async () => {
    const cases: Array<[object, RegExp]> = [
      [{ leafOid: false }, /receipt-signing OID/],
      [{ intermediateOid: false }, /WWDR OID/],
      [{ intermediateIsCa: false }, /not a CA/],
    ];
    for (const [opts, reason] of cases) {
      const p = await makePki(opts);
      const v = new AppleJwsVerifier({ rootCertificate: p.root });
      await assert.rejects(v.verify(await p.sign({ a: 1 })), reason);
    }
  });

  it('rejects non-ES256 headers and garbage', async () => {
    const h = Buffer.from(JSON.stringify({ alg: 'none', x5c: pki.x5c })).toString('base64url');
    await assert.rejects(verifier.verify(`${h}.${Buffer.from('{}').toString('base64url')}.`), /alg/);
    await assert.rejects(verifier.verify('not.a.jws'), AppleVerificationError);
    const noX5c = Buffer.from(JSON.stringify({ alg: 'ES256' })).toString('base64url');
    await assert.rejects(verifier.verify(`${noX5c}.e30.sig`), /x5c/);
  });
});

describe('Apple notification mapping', () => {
  const table: Array<[string, string | undefined]> = [
    ['SUBSCRIBED', 'active'], ['DID_RENEW', 'active'], ['OFFER_REDEEMED', 'active'],
    ['DID_FAIL_TO_RENEW', 'grace'], ['EXPIRED', 'expired'], ['GRACE_PERIOD_EXPIRED', 'expired'],
    ['REFUND', 'refunded'], ['REVOKE', 'revoked'], ['DID_CHANGE_RENEWAL_STATUS', undefined], ['TEST', undefined],
  ];
  for (const [type, status] of table) {
    it(`${type} -> ${status ?? 'ignored'}`, () => assert.equal(appleStatusFor(type), status));
  }

  const n = (notificationType: string, subtype?: string) => ({
    notificationType, subtype, notificationUUID: 'b3a1c1e0-0000-4000-8000-000000000001', signedDate: now,
  });

  it('grace period uses gracePeriodExpiresDate from the renewal info', () => {
    const r = mapAppleNotification(n('DID_FAIL_TO_RENEW', 'GRACE_PERIOD'), tx({ expiresDate: now - 1000 }), { gracePeriodExpiresDate: now + 16 * DAY });
    assert.ok(r.kind === 'event');
    assert.equal(r.event.status, 'grace');
    assert.equal(r.event.expires_at, iso(now + 16 * DAY));
  });

  it('refund expires at the revocation date', () => {
    const r = mapAppleNotification(n('REFUND'), tx({ revocationDate: now - 5000 }), undefined);
    assert.ok(r.kind === 'event');
    assert.equal(r.event.status, 'refunded');
    assert.equal(r.event.expires_at, iso(now - 5000));
  });

  it('ignores transactions without appAccountToken', () => {
    assert.equal(mapAppleNotification(n('SUBSCRIBED'), tx({ appAccountToken: undefined }), undefined).kind, 'ignore');
  });
});

describe('Apple routes', () => {
  let ctx: TestContext;
  before(async () => (ctx = await setup()));
  after(() => ctx.close());
  beforeEach(() => void (ctx.api.received.length = 0));

  const notify = async (payload: object) =>
    ctx.app.inject({ method: 'POST', url: '/billing/apple/notifications', payload: { signedPayload: await ctx.pki.sign(payload) } });

  it('SUBSCRIBED: verifies outer and nested JWS and forwards per contract', async () => {
    const res = await notify({
      notificationType: 'SUBSCRIBED', subtype: 'INITIAL_BUY', notificationUUID: '0d8a6c1e-1111-4222-8333-944455556666',
      signedDate: now, version: '2.0',
      data: { bundleId: BUNDLE, environment: 'Sandbox', signedTransactionInfo: await ctx.pki.sign(tx()), signedRenewalInfo: await ctx.pki.sign({ autoRenewStatus: 1 }) },
    });
    assert.equal(res.statusCode, 200, res.body);
    assert.deepEqual(forwarded(ctx.api)[0], {
      event_id: '0d8a6c1e-1111-4222-8333-944455556666', source: 'app_store', user_id: USER,
      product_id: 'com.slipstream.premium.monthly', status: 'active', expires_at: iso(now + 30 * DAY),
      original_transaction_id: '2000000000', occurred_at: iso(now),
    });
  });

  it('rejects a nested transaction signed outside the chain', async () => {
    const evil = await makePki({}, await makeRoot('Evil'));
    const res = await notify({
      notificationType: 'SUBSCRIBED', notificationUUID: '0d8a6c1e-1111-4222-8333-944455556667', signedDate: now,
      data: { bundleId: BUNDLE, signedTransactionInfo: await evil.sign(tx()) },
    });
    assert.equal(res.statusCode, 400);
    assert.equal(ctx.api.received.length, 0);
  });

  it('rejects another app\'s bundle id', async () => {
    const res = await notify({ notificationType: 'SUBSCRIBED', notificationUUID: 'x', signedDate: now, data: { bundleId: 'com.other' } });
    assert.equal(res.statusCode, 400);
  });

  it('client verify: binds appAccountToken to the JWT subject', async () => {
    const signed_transaction = await ctx.pki.sign(tx());
    const ok = await ctx.app.inject({
      method: 'POST', url: '/billing/apple/verify', payload: { signed_transaction },
      headers: { authorization: `Bearer ${await ctx.issuer.token(USER)}` },
    });
    assert.equal(ok.statusCode, 200, ok.body);
    assert.deepEqual(ok.json(), { status: 'active', expires_at: iso(now + 30 * DAY), applied: true });
    assert.equal(forwarded(ctx.api)[0]!.event_id, 'app_store:2000000001:active');

    const other = await ctx.app.inject({
      method: 'POST', url: '/billing/apple/verify', payload: { signed_transaction },
      headers: { authorization: `Bearer ${await ctx.issuer.token(OTHER_USER)}` },
    });
    assert.equal(other.statusCode, 403);
    assert.equal(other.json().error.code, 'forbidden');

    const anon = await ctx.app.inject({ method: 'POST', url: '/billing/apple/verify', payload: { signed_transaction } });
    assert.equal(anon.statusCode, 401);
    assert.equal(ctx.api.received.length, 1);
  });
});
