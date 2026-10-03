/**
 * Fake api that verifies the service HMAC *independently* of src/forwarder.ts
 * (re-implemented here from the contract text) and records what it received.
 */
import { createHmac, timingSafeEqual } from 'node:crypto';
import { createServer, type IncomingHttpHeaders, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

export interface Received {
  method: string;
  path: string;
  headers: IncomingHttpHeaders;
  body: string;
  signatureValid: boolean;
}

export interface FakeApi {
  url: URL;
  received: Received[];
  /** Status codes to answer with, in order; when exhausted, 200 {"applied": true}. */
  script: number[];
  close(): Promise<void>;
}

export function verifyContractSignature(secret: string, r: Omit<Received, 'signatureValid'>, nowS = Date.now() / 1000): boolean {
  const ts = r.headers['x-slipstream-timestamp'];
  const sig = r.headers['x-slipstream-signature'];
  if (r.headers['x-slipstream-service'] !== 'billing-webhooks') return false;
  if (typeof ts !== 'string' || typeof sig !== 'string' || !sig.startsWith('v1=')) return false;
  if (Math.abs(nowS - Number(ts)) > 300) return false;
  const expected = createHmac('sha256', secret).update(`${ts}.${r.method}.${r.path}.${r.body}`).digest();
  const got = Buffer.from(sig.slice(3), 'hex');
  return got.length === expected.length && timingSafeEqual(got, expected);
}

export async function startFakeApi(secret: string): Promise<FakeApi> {
  const api: Omit<FakeApi, 'url' | 'close'> = { received: [], script: [] };
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const r = {
        method: req.method ?? '',
        path: (req.url ?? '').split('?')[0]!,
        headers: req.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      };
      const signatureValid = verifyContractSignature(secret, r);
      api.received.push({ ...r, signatureValid });
      const status = signatureValid ? (api.script.shift() ?? 200) : 401;
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(status === 200 ? JSON.stringify({ applied: true }) : JSON.stringify({ error: { code: 'x', message: 'x' } }));
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address() as AddressInfo;
  return Object.assign(api, {
    url: new URL(`http://127.0.0.1:${port}`),
    close: () => new Promise<void>((r) => server.close(() => r())),
  });
}
