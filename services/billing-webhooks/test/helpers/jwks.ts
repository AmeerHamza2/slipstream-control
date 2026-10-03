/** Local JWKS server + token minting that mimics the Go api (EdDSA / Ed25519, kid). */
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { exportJWK, generateKeyPair, SignJWT, type CryptoKey } from 'jose';

export interface TestIssuer {
  url: URL;
  fetches: number;
  token(sub: string, opts?: { iss?: string; aud?: string; exp?: string | number; key?: CryptoKey; kid?: string }): Promise<string>;
  close(): Promise<void>;
}

export async function startJwksServer(): Promise<TestIssuer> {
  const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
  const jwk = { ...(await exportJWK(publicKey)), kid: 'k1', alg: 'EdDSA', use: 'sig' };
  const state = { fetches: 0 };
  const server = createServer((req, res) => {
    if (req.url === '/.well-known/jwks.json') {
      state.fetches++;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ keys: [jwk] }));
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address() as AddressInfo;

  return {
    url: new URL(`http://127.0.0.1:${port}`),
    get fetches() {
      return state.fetches;
    },
    token: (sub, o = {}) =>
      new SignJWT({ jti: crypto.randomUUID() })
        .setProtectedHeader({ alg: 'EdDSA', kid: o.kid ?? 'k1' })
        .setIssuer(o.iss ?? 'slipstream-control')
        .setAudience(o.aud ?? 'slipstream-app')
        .setSubject(sub)
        .setIssuedAt()
        .setExpirationTime(o.exp ?? '15m')
        .sign(o.key ?? privateKey),
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}
