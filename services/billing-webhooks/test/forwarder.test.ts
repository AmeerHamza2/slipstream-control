import assert from 'node:assert/strict';
import { after, before, beforeEach, describe, it } from 'node:test';
import type { EntitlementEvent } from '../src/entitlement.js';
import { ForwardRejectedError, ForwardUnavailableError, HttpForwarder, signRequest } from '../src/forwarder.js';
import { SECRET, USER } from './helpers/app.js';
import { startFakeApi, verifyContractSignature, type FakeApi } from './helpers/fakeApi.js';

const event: EntitlementEvent = {
  event_id: 'evt_f1', source: 'stripe', user_id: USER, product_id: 'premium_monthly', status: 'active',
  expires_at: '2026-11-02T12:00:00Z', original_transaction_id: 'sub_1', occurred_at: '2026-10-02T12:00:00Z',
};

describe('signRequest', () => {
  it('matches a known vector computed from the contract formula', () => {
    // printf '1700000000.POST./internal/v1/entitlements.{}' | openssl dgst -sha256 -hmac secret-secret-secret
    const h = signRequest('secret-secret-secret', 'post', '/internal/v1/entitlements', '{}', 1_700_000_000);
    assert.equal(h['X-Slipstream-Service'], 'billing-webhooks');
    assert.equal(h['X-Slipstream-Timestamp'], '1700000000');
    assert.equal(h['X-Slipstream-Signature'], 'v1=a974f98976ad265d95fad4f007fd8e3c1ec4339b9a17108f21be7dee49d841a8');
    assert.ok(
      verifyContractSignature('secret-secret-secret', {
        method: 'POST', path: '/internal/v1/entitlements', body: '{}',
        headers: {
          'x-slipstream-service': h['X-Slipstream-Service'], 'x-slipstream-timestamp': h['X-Slipstream-Timestamp'],
          'x-slipstream-signature': h['X-Slipstream-Signature'],
        },
      }, 1_700_000_000),
    );
  });
});

describe('HttpForwarder', () => {
  let api: FakeApi;
  const sleeps: number[] = [];
  const forwarder = () => new HttpForwarder({ apiUrl: api.url, secret: SECRET, sleep: async (ms) => void sleeps.push(ms) });

  before(async () => (api = await startFakeApi(SECRET)));
  after(() => api.close());
  beforeEach(() => {
    api.received.length = 0;
    api.script.length = 0;
    sleeps.length = 0;
  });

  it('POSTs the contract payload to /internal/v1/entitlements with a valid signature', async () => {
    const r = await forwarder().forward(event);
    assert.deepEqual(r, { applied: true });
    const got = api.received[0]!;
    assert.equal(got.method, 'POST');
    assert.equal(got.path, '/internal/v1/entitlements');
    assert.equal(got.signatureValid, true);
    assert.deepEqual(JSON.parse(got.body), event);
  });

  it('signs the real path when API_URL has a prefix', async () => {
    const f = new HttpForwarder({ apiUrl: new URL('/prefix', api.url), secret: SECRET, sleep: async () => {} });
    await f.forward(event);
    assert.equal(api.received[0]!.path, '/prefix/internal/v1/entitlements');
    assert.equal(api.received[0]!.signatureValid, true);
  });

  it('a wrong secret is rejected by the api and not retried', async () => {
    const f = new HttpForwarder({ apiUrl: api.url, secret: 'not-the-shared-secret', sleep: async () => {} });
    await assert.rejects(f.forward(event), ForwardRejectedError);
    assert.equal(api.received.length, 1);
  });

  it('retries 5xx with growing, jittered backoff and then succeeds', async () => {
    api.script.push(500, 503);
    assert.deepEqual(await forwarder().forward(event), { applied: true });
    assert.equal(api.received.length, 3);
    assert.equal(sleeps.length, 2);
    assert.ok(sleeps[0]! <= 200 && sleeps[1]! <= 400);
    assert.ok(api.received.every((r) => r.signatureValid));
  });

  it('does not retry a 400', async () => {
    api.script.push(400);
    await assert.rejects(forwarder().forward(event), (e: unknown) => e instanceof ForwardRejectedError && e.status === 400);
    assert.equal(api.received.length, 1);
  });

  it('gives up after 5 attempts', async () => {
    api.script.push(500, 500, 500, 500, 500, 500);
    await assert.rejects(forwarder().forward(event), (e: unknown) => e instanceof ForwardUnavailableError && e.attempts === 5);
    assert.equal(api.received.length, 5);
  });

  it('retries network errors', async () => {
    let calls = 0;
    const flaky: typeof fetch = async (input, init) => {
      if (++calls < 3) throw new TypeError('fetch failed');
      return fetch(input, init);
    };
    const f = new HttpForwarder({ apiUrl: api.url, secret: SECRET, fetchImpl: flaky, sleep: async () => {} });
    assert.deepEqual(await f.forward(event), { applied: true });
    assert.equal(calls, 3);
  });
});
