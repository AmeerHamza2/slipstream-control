import { createLocalJWKSet, errors as joseErrors, jwtVerify, type JWTVerifyGetKey } from 'jose';
import { isUuid } from '../entitlement.js';
import { HttpError, unauthorized, upstream } from '../errors.js';

export const JWT_ISSUER = 'slipstream-control';
export const JWT_AUDIENCE = 'slipstream-app';
export const JWKS_CACHE_MS = 5 * 60 * 1000;

export interface UserVerifier {
  /** Returns the user id (`sub`) of a valid access token, or throws HttpError(401). */
  verify(authorizationHeader: string | undefined): Promise<string>;
}

/** The key set could not be fetched and no usable cached copy exists (→ 503, not 401). */
export class JwksUnavailableError extends Error {}

export interface CachingJwksOptions {
  /** Refresh after this age (default 5 min, per the contract). Refreshes run in the background. */
  cacheMaxAgeMs?: number;
  /** Keep serving the last good key set this long when refreshes fail (default 1 h). */
  maxStaleMs?: number;
  /** At most one refetch per this period for an unknown `kid` (default 30 s; DoS guard). */
  cooldownMs?: number;
  /** After a failed fetch, wait this long before trying again (default 5 s; no stampede on a down api). */
  failureBackoffMs?: number;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
  now?: () => number;
}

/**
 * JWKS cache for the api's `/.well-known/jwks.json`, built for load:
 * - one fetch at a time (concurrent callers share it);
 * - stale-while-revalidate: an expired cache is served while a refresh runs in the
 *   background, and kept for `maxStaleMs` if the api is down, so an api blip does not
 *   turn into a wave of 401s/503s on client receipt verification;
 * - failures are negatively cached for `failureBackoffMs`, so a down api is not hit by
 *   every incoming request;
 * - fetch failures surface as `JwksUnavailableError` (→ 503), never as "invalid token".
 */
export class CachingJwks {
  private local: ReturnType<typeof createLocalJWKSet> | undefined;
  private fetchedAt = -Infinity;
  private lastAttemptAt = -Infinity;
  private lastFailedAt = -Infinity;
  private pending: Promise<void> | undefined;
  fetches = 0;
  failures = 0;
  private readonly o: Required<Omit<CachingJwksOptions, 'fetchImpl' | 'now'>>;
  private readonly fetchImpl: typeof fetch;
  private readonly now: () => number;

  constructor(
    private readonly url: URL,
    opts: CachingJwksOptions = {},
  ) {
    this.o = {
      cacheMaxAgeMs: opts.cacheMaxAgeMs ?? JWKS_CACHE_MS,
      maxStaleMs: opts.maxStaleMs ?? 60 * 60 * 1000,
      cooldownMs: opts.cooldownMs ?? 30_000,
      failureBackoffMs: opts.failureBackoffMs ?? 5_000,
      timeoutMs: opts.timeoutMs ?? 5_000,
    };
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.now = opts.now ?? Date.now;
  }

  /** `JWTVerifyGetKey` for `jwtVerify`. */
  readonly getKey: JWTVerifyGetKey = async (header, token) => {
    const age = this.now() - this.fetchedAt;
    if (!this.local || age > this.o.maxStaleMs) {
      await this.refresh(true); // nothing usable: must wait
    } else if (age > this.o.cacheMaxAgeMs) {
      void this.refresh(false).catch(() => undefined); // serve stale, refresh behind
    }
    const local = this.local;
    if (!local) throw new JwksUnavailableError('key set unavailable');
    try {
      return await local(header, token);
    } catch (err) {
      // Unknown kid: maybe the api rotated keys. Refetch, but at most once per cooldown.
      if (err instanceof joseErrors.JWKSNoMatchingKey && this.now() - this.lastAttemptAt > this.o.cooldownMs) {
        await this.refresh(false).catch(() => undefined);
        if (this.local) return this.local(header, token);
      }
      throw err;
    }
  };

  private refresh(mustHaveKeys: boolean): Promise<void> {
    if (!this.pending) {
      if (this.now() - this.lastFailedAt < this.o.failureBackoffMs) {
        return mustHaveKeys && !this.usable()
          ? Promise.reject(new JwksUnavailableError('key set unavailable (recent fetch failed)'))
          : Promise.resolve();
      }
      this.pending = this.load().finally(() => (this.pending = undefined));
    }
    return this.pending.catch((err: unknown) => {
      if (mustHaveKeys && !this.usable()) throw err;
    });
  }

  private usable(): boolean {
    return this.local !== undefined && this.now() - this.fetchedAt <= this.o.maxStaleMs;
  }

  private async load(): Promise<void> {
    this.lastAttemptAt = this.now();
    this.fetches++;
    try {
      const res = await this.fetchImpl(this.url, {
        headers: { accept: 'application/json, application/jwk-set+json' },
        redirect: 'manual',
        signal: AbortSignal.timeout(this.o.timeoutMs),
      });
      if (res.status !== 200) {
        await res.body?.cancel().catch(() => undefined);
        throw new JwksUnavailableError(`JWKS HTTP ${res.status}`);
      }
      const json = (await res.json()) as unknown;
      this.local = createLocalJWKSet(json as Parameters<typeof createLocalJWKSet>[0]); // validates shape
      this.fetchedAt = this.now();
    } catch (err) {
      this.failures++;
      this.lastFailedAt = this.now();
      throw err instanceof JwksUnavailableError ? err : new JwksUnavailableError(`JWKS fetch failed: ${(err as Error).name}`);
    }
  }
}

export function jwksUrl(apiUrl: URL): URL {
  return new URL('.well-known/jwks.json', apiUrl.href.endsWith('/') ? apiUrl : apiUrl.href + '/');
}

/** Remote JWKS from the api, cached for 5 minutes (see `CachingJwks`). */
export function remoteJwks(apiUrl: URL, opts?: CachingJwksOptions): JWTVerifyGetKey {
  return new CachingJwks(jwksUrl(apiUrl), opts).getKey;
}

export class JwtUserVerifier implements UserVerifier {
  constructor(private readonly keys: JWTVerifyGetKey) {}

  async verify(header: string | undefined): Promise<string> {
    const m = /^Bearer ([A-Za-z0-9._~+/-]+=*)$/.exec(header ?? '');
    if (!m?.[1]) throw unauthorized('missing bearer token');
    try {
      const { payload } = await jwtVerify(m[1], this.keys, {
        issuer: JWT_ISSUER,
        audience: JWT_AUDIENCE,
        algorithms: ['EdDSA'], // pin the algorithm; never trust the token's own `alg`
        requiredClaims: ['sub', 'exp', 'iat'],
      });
      if (!isUuid(payload.sub)) throw unauthorized('invalid subject');
      return payload.sub;
    } catch (err) {
      if (err instanceof HttpError) throw err;
      if (err instanceof JwksUnavailableError || err instanceof joseErrors.JWKSTimeout) {
        throw upstream(503, 'key set unavailable', 5);
      }
      if (err instanceof joseErrors.JWTExpired) throw unauthorized('token expired');
      if (err instanceof joseErrors.JOSEError) throw unauthorized('invalid token');
      throw upstream(503, 'key set unavailable', 5); // unexpected (network)
    }
  }
}
