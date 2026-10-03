import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { generateKeyPair, SignJWT, type CryptoKey } from 'jose';
import { CachingJwks, JwtUserVerifier, remoteJwks } from '../src/auth/userJwt.js';
import { HttpError } from '../src/errors.js';
import { USER } from './helpers/app.js';
import { startJwksServer, type TestIssuer } from './helpers/jwks.js';

describe('user JWT verification against the api JWKS', () => {
  let issuer: TestIssuer;
  let verifier: JwtUserVerifier;
  before(async () => {
    issuer = await startJwksServer();
    verifier = new JwtUserVerifier(remoteJwks(issuer.url));
  });
  after(() => issuer.close());

  const rejects401 = (p: Promise<unknown>) =>
    assert.rejects(p, (e: unknown) => e instanceof HttpError && e.statusCode === 401);

  it('accepts a valid token and returns sub; caches the JWKS', async () => {
    assert.equal(await verifier.verify(`Bearer ${await issuer.token(USER)}`), USER);
    assert.equal(await verifier.verify(`Bearer ${await issuer.token(USER)}`), USER);
    assert.equal(issuer.fetches, 1);
  });

  it('rejects wrong issuer, wrong audience and expired tokens', async () => {
    await rejects401(verifier.verify(`Bearer ${await issuer.token(USER, { iss: 'someone-else' })}`));
    await rejects401(verifier.verify(`Bearer ${await issuer.token(USER, { aud: 'admin' })}`));
    await rejects401(verifier.verify(`Bearer ${await issuer.token(USER, { exp: Math.floor(Date.now() / 1000) - 60 })}`));
  });

  it('rejects tokens signed by a key not in the JWKS, and non-EdDSA algorithms', async () => {
    const { privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
    await rejects401(verifier.verify(`Bearer ${await issuer.token(USER, { key: privateKey })}`));
    const hs = await new SignJWT({}).setProtectedHeader({ alg: 'HS256', kid: 'k1' }).setSubject(USER)
      .setIssuer('slipstream-control').setAudience('slipstream-app').setIssuedAt().setExpirationTime('5m')
      .sign(new TextEncoder().encode('x'.repeat(32)));
    await rejects401(verifier.verify(`Bearer ${hs}`));
  });

  it('rejects missing / malformed headers and non-UUID subjects', async () => {
    await rejects401(verifier.verify(undefined));
    await rejects401(verifier.verify('Basic abc'));
    await rejects401(verifier.verify(`Bearer ${await issuer.token('not-a-uuid')}`));
  });
});

describe('JWKS cache resilience', () => {
  const pair = async () => {
    const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
    const { exportJWK } = await import('jose');
    return { jwk: { ...(await exportJWK(publicKey)), kid: 'k1', alg: 'EdDSA' }, privateKey };
  };
  const tokenWith = (key: CryptoKey) => new SignJWT({}).setProtectedHeader({ alg: 'EdDSA', kid: 'k1' }).setSubject(USER)
    .setIssuer('slipstream-control').setAudience('slipstream-app').setIssuedAt().setExpirationTime('5m').sign(key);

  it('serves stale keys while the api is down, negatively caches failures, and 503s (not 401s) with no keys', async () => {
    const { jwk, privateKey } = await pair();
    let t = 0;
    let up = true;
    let calls = 0;
    const fakeFetch: typeof fetch = async () => {
      calls++;
      if (!up) throw new TypeError('fetch failed');
      return new Response(JSON.stringify({ keys: [jwk] }), { status: 200 });
    };
    const jwks = new CachingJwks(new URL('http://api.invalid/.well-known/jwks.json'), { fetchImpl: fakeFetch, now: () => t });
    const v = new JwtUserVerifier(jwks.getKey);
    const tok = `Bearer ${await tokenWith(privateKey)}`;
    assert.equal(await v.verify(tok), USER);
    up = false;
    t += 10 * 60 * 1000; // past the 5 min cache age: a background refresh fails, stale keys still serve
    for (let i = 0; i < 50; i++) assert.equal(await v.verify(tok), USER);
    await new Promise((r) => setImmediate(r));
    assert.equal(calls, 2, 'one failed refresh, then backoff: no stampede');
    t += 2 * 60 * 60 * 1000; // beyond max staleness: nothing usable
    await assert.rejects(v.verify(tok), (e: unknown) => e instanceof HttpError && e.statusCode === 503);
    await assert.rejects(v.verify(tok), (e: unknown) => e instanceof HttpError && e.statusCode === 503);
    assert.equal(calls, 3, 'second call inside failure backoff does not refetch');
    up = true;
    t += 6_000;
    assert.equal(await v.verify(tok), USER);
  });

  it('maps a non-200 JWKS response to 503, and coalesces concurrent fetches', async () => {
    let calls = 0;
    const fakeFetch: typeof fetch = async () => {
      calls++;
      await new Promise((r) => setTimeout(r, 10));
      return new Response('oops', { status: 500 });
    };
    const v = new JwtUserVerifier(new CachingJwks(new URL('http://api.invalid/jwks'), { fetchImpl: fakeFetch }).getKey);
    const { privateKey } = await pair();
    const tok = `Bearer ${await tokenWith(privateKey)}`;
    const rs = await Promise.allSettled(Array.from({ length: 20 }, () => v.verify(tok)));
    assert.ok(rs.every((r) => r.status === 'rejected' && (r.reason as HttpError).statusCode === 503));
    assert.equal(calls, 1);
  });
});
