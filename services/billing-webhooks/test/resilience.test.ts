import assert from 'node:assert/strict';
import { after, before, beforeEach, describe, it } from 'node:test';
import type { EntitlementEvent } from '../src/entitlement.js';
import { ForwardUnavailableError, HttpForwarder } from '../src/forwarder.js';
import { Bulkhead, BulkheadFullError, CircuitBreaker, CircuitOpenError } from '../src/resilience.js';
import { SECRET, setup, STRIPE_SECRET, USER, type TestContext } from './helpers/app.js';
import { startFakeApi, type FakeApi } from './helpers/fakeApi.js';
import { stripeSignatureHeader } from '../src/stripe/signature.js';

const event: EntitlementEvent = {
  event_id: 'evt_r', source: 'stripe', user_id: USER, product_id: 'premium_monthly', status: 'active',
  expires_at: '2026-11-02T12:00:00Z', original_transaction_id: 'sub_1', occurred_at: '2026-10-02T12:00:00Z',
};
const tick = () => new Promise((r) => setImmediate(r));

describe('Bulkhead', () => {
  it('caps concurrency, queues up to maxQueue, sheds beyond it', async () => {
    const b = new Bulkhead({ maxConcurrent: 2, maxQueue: 1 });
    let running = 0;
    let peak = 0;
    const gates: Array<() => void> = [];
    const job = () => b.run(async () => {
      running++;
      peak = Math.max(peak, running);
      await new Promise<void>((r) => gates.push(r));
      running--;
    }, 10_000);
    const p = [job(), job(), job()];
    await tick();
    assert.equal(b.inFlight, 2);
    assert.equal(b.queued, 1);
    await assert.rejects(job(), (e: unknown) => e instanceof BulkheadFullError && e.reason === 'queue_full');
    while (gates.length) {
      gates.shift()!();
      await tick();
      await tick();
    }
    await Promise.all(p);
    assert.equal(peak, 2);
    assert.equal(b.inFlight, 0);
    assert.equal(b.queued, 0);
  });

  it('times out waiters and does not leak the slot', async () => {
    const b = new Bulkhead({ maxConcurrent: 1, maxQueue: 10 });
    let release!: () => void;
    const holder = b.run(() => new Promise<void>((r) => (release = r)), 1000);
    await tick();
    await assert.rejects(b.run(async () => 1, 20), (e: unknown) => e instanceof BulkheadFullError && e.reason === 'queue_timeout');
    assert.equal(b.queued, 0);
    release();
    await holder;
    assert.equal(await b.run(async () => 42, 0), 42);
    assert.equal(b.inFlight, 0);
  });
});

describe('CircuitBreaker', () => {
  it('opens after N consecutive failures, half-opens with a single probe, closes on success', () => {
    let t = 0;
    const cb = new CircuitBreaker({ failureThreshold: 3, openMs: 1000, now: () => t, random: () => 0.5 });
    cb.admit(); cb.failure();
    cb.admit(); cb.success(); // success resets the streak
    for (let i = 0; i < 3; i++) { cb.admit(); cb.failure(); }
    assert.equal(cb.state, 'open');
    assert.throws(() => cb.admit(), CircuitOpenError);
    t = 999;
    assert.equal(cb.state, 'open');
    t = 1000;
    assert.equal(cb.state, 'half_open');
    cb.admit(); // the probe
    assert.throws(() => cb.admit(), CircuitOpenError); // everyone else still fails fast
    cb.failure(); // probe failed: open again
    assert.equal(cb.state, 'open');
    t = 2001;
    cb.admit();
    cb.success();
    assert.equal(cb.state, 'closed');
    assert.equal(cb.opened, 2);
  });

  it('jitters the open period by ±20%', () => {
    const lo = new CircuitBreaker({ failureThreshold: 1, openMs: 1000, now: () => 0, random: () => 0 });
    const hi = new CircuitBreaker({ failureThreshold: 1, openMs: 1000, now: () => 0, random: () => 1 });
    lo.failure(); hi.failure();
    assert.equal(lo.retryAfterMs(), 800);
    assert.equal(hi.retryAfterMs(), 1200);
  });
});

describe('HttpForwarder under failure', () => {
  let api: FakeApi;
  before(async () => (api = await startFakeApi(SECRET)));
  after(() => api.close());
  beforeEach(() => {
    api.received.length = 0;
    api.script.length = 0;
  });

  it('opens the circuit on a down api and then fails fast without sending', async () => {
    const f = new HttpForwarder({ apiUrl: api.url, secret: SECRET, sleep: async () => {}, breakerThreshold: 4, breakerOpenMs: 60_000 });
    api.script.push(...Array(20).fill(503));
    // The 5th attempt finds the circuit open after 4 consecutive failures.
    await assert.rejects(f.forward(event), (e: unknown) => e instanceof ForwardUnavailableError && e.reason === 'circuit_open');
    const sent = api.received.length;
    assert.equal(sent, 4);
    assert.equal(f.breaker.state, 'open');
    await assert.rejects(f.forward({ ...event, event_id: 'evt_r3' }),
      (e: unknown) => e instanceof ForwardUnavailableError && e.reason === 'circuit_open' && e.retryAfterMs > 0);
    assert.equal(api.received.length, sent, 'no request while open');
    assert.ok(f.stats.shed.circuit_open >= 1);
  });

  it('stops retrying at the deadline', async () => {
    let t = Date.now();
    const f = new HttpForwarder({
      apiUrl: api.url, secret: SECRET, deadlineMs: 1000, maxAttempts: 50, baseDelayMs: 400, maxDelayMs: 400,
      now: () => t, sleep: async (ms) => void (t += ms), breakerThreshold: 1000,
    });
    api.script.push(...Array(50).fill(500));
    await assert.rejects(f.forward(event), (e: unknown) => e instanceof ForwardUnavailableError && e.reason === 'deadline');
    assert.ok(api.received.length < 50 && api.received.length >= 1);
  });

  it('sheds with "overloaded" when the queue is full, and bounds concurrent api requests', async () => {
    let active = 0;
    let peak = 0;
    const slow: typeof fetch = async (input, init) => {
      active++;
      peak = Math.max(peak, active);
      await new Promise((r) => setTimeout(r, 20));
      try {
        return await fetch(input, init);
      } finally {
        active--;
      }
    };
    const f = new HttpForwarder({ apiUrl: api.url, secret: SECRET, fetchImpl: slow, maxConcurrent: 4, maxQueue: 8 });
    const results = await Promise.allSettled(Array.from({ length: 30 }, (_, i) => f.forward({ ...event, event_id: `e${i}` })));
    const ok = results.filter((r) => r.status === 'fulfilled').length;
    const shed = results.filter((r) => r.status === 'rejected' && (r.reason as ForwardUnavailableError).reason === 'overloaded').length;
    assert.equal(ok, 12);
    assert.equal(shed, 18);
    assert.equal(peak, 4);
    assert.equal(api.received.length, 12);
  });

  it('treats 429 as retryable', async () => {
    const f = new HttpForwarder({ apiUrl: api.url, secret: SECRET, sleep: async () => {} });
    api.script.push(429);
    assert.deepEqual(await f.forward(event), { applied: true });
    assert.equal(api.received.length, 2);
  });
});

describe('server limits', () => {
  let ctx: TestContext;
  before(async () => (ctx = await setup()));
  after(() => ctx.close());

  it('rejects bodies over 256 KiB with 413 before verifying anything', async () => {
    const payload = JSON.stringify({ id: 'evt_big', pad: 'x'.repeat(300 * 1024) });
    const res = await ctx.app.inject({
      method: 'POST', url: '/billing/stripe/webhook', payload,
      headers: { 'content-type': 'application/json', 'stripe-signature': stripeSignatureHeader(Buffer.from(payload), STRIPE_SECRET, Math.floor(Date.now() / 1000)) },
    });
    assert.equal(res.statusCode, 413);
    assert.equal(ctx.api.received.length, 0);
  });

  it('configures request and keep-alive timeouts on the http server', () => {
    const server = ctx.app.server;
    assert.equal(server.requestTimeout, 15_000);
    assert.equal(server.keepAliveTimeout, 72_000);
    assert.ok(server.headersTimeout <= server.requestTimeout);
  });

  it('serves Prometheus metrics', async () => {
    await ctx.app.inject({ method: 'GET', url: '/healthz' });
    const res = await ctx.app.inject({ method: 'GET', url: '/metrics' });
    assert.equal(res.statusCode, 200);
    assert.match(res.body, /billing_http_responses_total\{route="\/healthz",status="200"\} \d+/);
  });
});
