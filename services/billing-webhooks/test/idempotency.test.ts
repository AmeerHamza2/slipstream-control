import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { after, before, describe, it } from 'node:test';
import { Redis } from 'ioredis';
import type { EntitlementEvent } from '../src/entitlement.js';
import type { Forwarder } from '../src/forwarder.js';
import { IDEMPOTENCY_TTL_SECONDS, MemoryIdempotencyStore, RedisIdempotencyStore, type IdempotencyStore } from '../src/idempotency.js';
import { EventPipeline } from '../src/pipeline.js';
import { USER } from './helpers/app.js';

const silent = { info() {}, warn() {}, error() {}, debug() {}, trace() {}, fatal() {}, child() { return silent; }, level: 'silent', silent() {} } as never;

const event = (id: string): EntitlementEvent => ({
  event_id: id, source: 'stripe', user_id: USER, product_id: 'p', status: 'active',
  expires_at: '2030-01-01T00:00:00Z', original_transaction_id: 'sub_1', occurred_at: '2026-10-02T00:00:00Z',
});

describe('MemoryIdempotencyStore', () => {
  it('SET NX semantics with TTL', async () => {
    let t = 0;
    const s = new MemoryIdempotencyStore(10, () => t);
    assert.equal(await s.isProcessed('a'), false);
    await s.markProcessed('a');
    assert.equal(await s.isProcessed('a'), true);
    t = 10_001;
    assert.equal(await s.isProcessed('a'), false);
  });
});

describe('EventPipeline idempotency', () => {
  const counting = () => {
    const calls: string[] = [];
    let fail = false;
    const f: Forwarder & { calls: string[]; fail(v: boolean): void } = {
      calls,
      fail: (v) => void (fail = v),
      forward: async (e) => {
        calls.push(e.event_id);
        if (fail) throw new Error('down');
        return { applied: true };
      },
    };
    return f;
  };

  it('forwards once, short-circuits duplicates, and only remembers after success', async () => {
    const fwd = counting();
    const store = new MemoryIdempotencyStore();
    const p = new EventPipeline(fwd, store);

    fwd.fail(true);
    await assert.rejects(p.process(event('e1'), silent), (e: { statusCode?: number }) => e.statusCode === 503);
    assert.equal(await store.isProcessed('e1'), false);

    fwd.fail(false);
    assert.equal((await p.process(event('e1'), silent)).outcome, 'forwarded');
    assert.equal((await p.process(event('e1'), silent)).outcome, 'duplicate');
    assert.deepEqual(fwd.calls, ['e1', 'e1']);
  });

  it('fails open when the store is down (the api dedups)', async () => {
    const broken: IdempotencyStore = {
      isProcessed: async () => { throw new Error('ECONNREFUSED'); },
      markProcessed: async () => { throw new Error('ECONNREFUSED'); },
      ping: async () => false,
    };
    const fwd = counting();
    const r = await new EventPipeline(fwd, broken).process(event('e2'), silent);
    assert.equal(r.outcome, 'forwarded');
  });
});

describe('RedisIdempotencyStore (integration)', { skip: !process.env.REDIS_URL && 'set REDIS_URL to run' }, () => {
  let redis: Redis;
  const prefix = `test:billing-webhooks:${randomUUID()}:`;
  before(() => {
    redis = new Redis(process.env.REDIS_URL!, { maxRetriesPerRequest: 1 });
  });
  after(async () => {
    const keys = await redis.keys(`${prefix}*`);
    if (keys.length) await redis.del(...keys);
    await redis.quit();
  });

  it('SET NX with a 7-day TTL', async () => {
    const s = new RedisIdempotencyStore(redis, prefix);
    assert.equal(await s.ping(), true);
    assert.equal(await s.isProcessed('evt_r1'), false);
    await s.markProcessed('evt_r1');
    assert.equal(await s.isProcessed('evt_r1'), true);
    const ttl = await redis.ttl(`${prefix}evt_r1`);
    assert.ok(ttl > IDEMPOTENCY_TTL_SECONDS - 5 && ttl <= IDEMPOTENCY_TTL_SECONDS);
    await redis.expire(`${prefix}evt_r1`, 100);
    await s.markProcessed('evt_r1'); // NX: must not reset the TTL
    assert.ok((await redis.ttl(`${prefix}evt_r1`)) <= 100);
  });
});
