import type { FastifyInstance } from 'fastify';
import { AppleJwsVerifier } from '../../src/apple/jws.js';
import { JwtUserVerifier, remoteJwks } from '../../src/auth/userJwt.js';
import { HttpForwarder } from '../../src/forwarder.js';
import type { GooglePlayClient, SubscriptionPurchaseV2 } from '../../src/google/client.js';
import { GooglePlayUnavailableError } from '../../src/google/client.js';
import { MemoryIdempotencyStore } from '../../src/idempotency.js';
import { Metrics } from '../../src/metrics.js';
import { EventPipeline } from '../../src/pipeline.js';
import { buildApp } from '../../src/server.js';
import { makePki, type TestPki } from './certs.js';
import { startFakeApi, type FakeApi } from './fakeApi.js';
import { startJwksServer, type TestIssuer } from './jwks.js';

export const SECRET = 'billing-service-secret-for-tests';
export const STRIPE_SECRET = 'whsec_test_secret';
export const PUSH_TOKEN = 'google-push-token-0123456789';
export const PACKAGE = 'com.slipstream.vpn';
export const BUNDLE = 'com.slipstream.vpn';
export const USER = '6f1c2d3e-4b5a-4c6d-8e7f-901a2b3c4d5e';
export const OTHER_USER = '11111111-2222-4333-8444-555555555555';

export class FakeGooglePlay implements GooglePlayClient {
  purchases = new Map<string, SubscriptionPurchaseV2>();
  acknowledged: string[] = [];
  down = false;

  async getSubscription(_pkg: string, token: string) {
    if (this.down) throw new GooglePlayUnavailableError('down');
    return this.purchases.get(token) ?? null;
  }
  async acknowledge(_pkg: string, _productId: string, token: string) {
    this.acknowledged.push(token);
  }
}

export interface TestContext {
  app: FastifyInstance;
  api: FakeApi;
  pki: TestPki;
  issuer: TestIssuer;
  google: FakeGooglePlay;
  store: MemoryIdempotencyStore;
  close(): Promise<void>;
}

export async function setup(): Promise<TestContext> {
  const [api, pki, issuer] = await Promise.all([startFakeApi(SECRET), makePki(), startJwksServer()]);
  const google = new FakeGooglePlay();
  const store = new MemoryIdempotencyStore();
  const forwarder = new HttpForwarder({ apiUrl: api.url, secret: SECRET, sleep: async () => {} });
  const app = buildApp({
    stripeWebhookSecret: STRIPE_SECRET,
    googlePushToken: PUSH_TOKEN,
    googlePackageName: PACKAGE,
    appleBundleId: BUNDLE,
    pipeline: new EventPipeline(forwarder, store),
    apple: new AppleJwsVerifier({ rootCertificate: pki.root }),
    google,
    users: new JwtUserVerifier(remoteJwks(issuer.url)),
    store,
    metrics: new Metrics(),
  });
  await app.ready();
  return {
    app, api, pki, issuer, google, store,
    close: async () => {
      await app.close();
      await Promise.all([api.close(), issuer.close()]);
    },
  };
}

export const forwarded = (api: FakeApi) => api.received.map((r) => JSON.parse(r.body) as Record<string, unknown>);
