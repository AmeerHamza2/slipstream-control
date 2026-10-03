import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { ConfigError, loadConfig } from '../src/config.js';
import { setup, type TestContext } from './helpers/app.js';

describe('http plumbing', () => {
  let ctx: TestContext;
  before(async () => (ctx = await setup()));
  after(() => ctx.close());

  it('GET /healthz', async () => {
    const res = await ctx.app.inject({ method: 'GET', url: '/healthz' });
    assert.equal(res.statusCode, 200);
    assert.deepEqual(res.json(), { status: 'ok', redis: 'up' });
  });

  it('echoes a well-formed X-Request-Id and mints one otherwise', async () => {
    const a = await ctx.app.inject({ method: 'GET', url: '/healthz', headers: { 'x-request-id': 'req-123' } });
    assert.equal(a.headers['x-request-id'], 'req-123');
    const b = await ctx.app.inject({ method: 'GET', url: '/healthz', headers: { 'x-request-id': 'bad\nvalue' } });
    assert.match(String(b.headers['x-request-id']), /^[0-9a-f-]{36}$/);
  });

  it('contract error shape for 404 and invalid JSON', async () => {
    const nf = await ctx.app.inject({ method: 'GET', url: '/nope', headers: { 'x-request-id': 'r1' } });
    assert.deepEqual(nf.json(), { error: { code: 'not_found', message: 'route not found', request_id: 'r1' } });
    const bad = await ctx.app.inject({
      method: 'POST', url: '/billing/apple/notifications', payload: '{nope', headers: { 'content-type': 'application/json' },
    });
    assert.equal(bad.statusCode, 400);
    assert.equal(bad.json().error.code, 'invalid_request');
  });
});

describe('config', () => {
  const valid = {
    API_URL: 'http://api:8080', BILLING_SERVICE_SECRET: 'x'.repeat(32), STRIPE_WEBHOOK_SECRET: 'whsec_abcdef',
    APPLE_ROOT_CA_PATH: '/etc/apple/AppleRootCA-G3.cer', GOOGLE_PUSH_TOKEN: 'y'.repeat(32), REDIS_URL: 'redis://redis:6379',
  };
  it('defaults PORT to 8081', () => assert.equal(loadConfig(valid).port, 8081));
  it('lists every problem at once', () => {
    assert.throws(() => loadConfig({ ...valid, API_URL: 'nope', BILLING_SERVICE_SECRET: 'short', REDIS_URL: undefined }),
      (e: unknown) => e instanceof ConfigError && /API_URL/.test(e.message) && /BILLING_SERVICE_SECRET/.test(e.message) && /REDIS_URL/.test(e.message));
  });
});
