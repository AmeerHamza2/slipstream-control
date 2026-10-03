import { readFileSync } from 'node:fs';
import { importPKCS8, SignJWT } from 'jose';

/** Subset of androidpublisher v3 `SubscriptionPurchaseV2` that we use. */
export interface SubscriptionPurchaseV2 {
  subscriptionState?:
    | 'SUBSCRIPTION_STATE_UNSPECIFIED'
    | 'SUBSCRIPTION_STATE_PENDING'
    | 'SUBSCRIPTION_STATE_ACTIVE'
    | 'SUBSCRIPTION_STATE_PAUSED'
    | 'SUBSCRIPTION_STATE_IN_GRACE_PERIOD'
    | 'SUBSCRIPTION_STATE_ON_HOLD'
    | 'SUBSCRIPTION_STATE_CANCELED'
    | 'SUBSCRIPTION_STATE_EXPIRED'
    | 'SUBSCRIPTION_STATE_PENDING_PURCHASE_CANCELED';
  lineItems?: Array<{ productId?: string; expiryTime?: string }>;
  acknowledgementState?: 'ACKNOWLEDGEMENT_STATE_PENDING' | 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED';
  externalAccountIdentifiers?: { obfuscatedExternalAccountId?: string };
  testPurchase?: object;
}

export interface GooglePlayClient {
  /** `null` if Google does not know the token (404/410). Throws on transport/5xx errors. */
  getSubscription(packageName: string, purchaseToken: string): Promise<SubscriptionPurchaseV2 | null>;
  /** Purchases not acknowledged within 3 days are refunded automatically by Google. */
  acknowledge(packageName: string, productId: string, purchaseToken: string): Promise<void>;
}

export class GooglePlayUnavailableError extends Error {}

interface ServiceAccountKey {
  client_email: string;
  private_key: string;
  token_uri?: string;
}

const SCOPE = 'https://www.googleapis.com/auth/androidpublisher';
const API = 'https://androidpublisher.googleapis.com/androidpublisher/v3/applications';

/**
 * Real client: service-account JWT (RS256) -> OAuth2 access token (cached until shortly
 * before expiry) -> Android Publisher REST. No googleapis SDK, so the flow is explicit.
 */
export class HttpGooglePlayClient implements GooglePlayClient {
  private token: { value: string; expiresAt: number } | undefined;
  private inflight: Promise<string> | undefined;

  constructor(
    private readonly key: ServiceAccountKey,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {}

  static fromFile(path: string): HttpGooglePlayClient {
    const key = JSON.parse(readFileSync(path, 'utf8')) as ServiceAccountKey;
    if (!key.client_email || !key.private_key) throw new Error('service account key is missing fields');
    return new HttpGooglePlayClient(key);
  }

  async getSubscription(packageName: string, purchaseToken: string): Promise<SubscriptionPurchaseV2 | null> {
    const url = `${API}/${enc(packageName)}/purchases/subscriptionsv2/tokens/${enc(purchaseToken)}`;
    const res = await this.call(url, { method: 'GET' });
    if (res.status === 404 || res.status === 410) return null;
    if (!res.ok) throw new GooglePlayUnavailableError(`androidpublisher HTTP ${res.status}`);
    return (await res.json()) as SubscriptionPurchaseV2;
  }

  async acknowledge(packageName: string, productId: string, purchaseToken: string): Promise<void> {
    const url = `${API}/${enc(packageName)}/purchases/subscriptions/${enc(productId)}/tokens/${enc(purchaseToken)}:acknowledge`;
    const res = await this.call(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    if (!res.ok) throw new GooglePlayUnavailableError(`acknowledge HTTP ${res.status}`);
  }

  private async call(url: string, init: RequestInit): Promise<Response> {
    const token = await this.accessToken();
    try {
      return await this.fetchImpl(url, {
        ...init,
        headers: { ...(init.headers as Record<string, string>), Authorization: `Bearer ${token}` },
        signal: AbortSignal.timeout(10_000),
      });
    } catch (err) {
      throw new GooglePlayUnavailableError(`androidpublisher request failed: ${(err as Error).name}`);
    }
  }

  private async accessToken(): Promise<string> {
    if (this.token && this.token.expiresAt - 60_000 > Date.now()) return this.token.value;
    this.inflight ??= this.fetchToken().finally(() => (this.inflight = undefined));
    return this.inflight;
  }

  private async fetchToken(): Promise<string> {
    const tokenUri = this.key.token_uri ?? 'https://oauth2.googleapis.com/token';
    const assertion = await new SignJWT({ scope: SCOPE })
      .setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
      .setIssuer(this.key.client_email)
      .setAudience(tokenUri)
      .setIssuedAt()
      .setExpirationTime('1h')
      .sign(await importPKCS8(this.key.private_key, 'RS256'));

    const res = await this.fetchImpl(tokenUri, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion }),
      signal: AbortSignal.timeout(10_000),
    }).catch((err: Error) => {
      throw new GooglePlayUnavailableError(`token request failed: ${err.name}`);
    });
    if (!res.ok) throw new GooglePlayUnavailableError(`token endpoint HTTP ${res.status}`);
    const body = (await res.json()) as { access_token: string; expires_in: number };
    this.token = { value: body.access_token, expiresAt: Date.now() + body.expires_in * 1000 };
    return body.access_token;
  }
}

/** Used when no service account is configured: every lookup is a retryable 503. */
export class UnconfiguredGooglePlayClient implements GooglePlayClient {
  async getSubscription(): Promise<never> {
    throw new GooglePlayUnavailableError('Google Play client not configured');
  }
  async acknowledge(): Promise<never> {
    throw new GooglePlayUnavailableError('Google Play client not configured');
  }
}

const enc = encodeURIComponent;
