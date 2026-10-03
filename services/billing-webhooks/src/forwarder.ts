import { createHmac } from 'node:crypto';
import type { EntitlementEvent } from './entitlement.js';
import { Bulkhead, BulkheadFullError, CircuitBreaker, CircuitOpenError } from './resilience.js';

export const SERVICE_NAME = 'billing-webhooks';

/**
 * Service-to-service signature (docs/CONTRACT.md, "Service-to-service"):
 *   v1=hex(HMAC_SHA256(secret, timestamp + "." + METHOD + "." + path + "." + body))
 * `path` excludes the query string.
 */
export function signRequest(
  secret: string,
  method: string,
  path: string,
  body: string,
  timestamp: number,
): Record<string, string> {
  const mac = createHmac('sha256', secret)
    .update(`${timestamp}.${method.toUpperCase()}.${path}.${body}`)
    .digest('hex');
  return {
    'X-Slipstream-Service': SERVICE_NAME,
    'X-Slipstream-Timestamp': String(timestamp),
    'X-Slipstream-Signature': `v1=${mac}`,
  };
}

export interface ForwardResult {
  applied: boolean;
  reason?: string;
}

/** The api answered 4xx: retrying the same bytes will not help. */
export class ForwardRejectedError extends Error {
  constructor(readonly status: number) {
    super(`api rejected entitlement with HTTP ${status}`);
  }
}

export type UnavailableReason = 'exhausted' | 'deadline' | 'circuit_open' | 'overloaded';

/**
 * The api did not accept the event but might later: every attempt failed (5xx, 429,
 * network, timeout), the delivery deadline ran out, the circuit is open, or too many
 * forwards are already queued. Answered 503 + Retry-After so the store redelivers.
 */
export class ForwardUnavailableError extends Error {
  constructor(
    readonly attempts: number,
    readonly lastError: string,
    readonly reason: UnavailableReason = 'exhausted',
    readonly retryAfterMs = 0,
  ) {
    super(`api unavailable after ${attempts} attempts (${reason}): ${lastError}`);
  }
}

export interface Forwarder {
  forward(event: EntitlementEvent): Promise<ForwardResult>;
}

/** Counters exported on /metrics. */
export interface ForwarderStats {
  attempts: Record<'ok' | 'rejected' | 'retryable' | 'network', number>;
  shed: Record<'circuit_open' | 'overloaded', number>;
}

export interface HttpForwarderOptions {
  apiUrl: URL;
  secret: string;
  maxAttempts?: number;
  baseDelayMs?: number;
  maxDelayMs?: number;
  /** Per-attempt timeout (capped by the remaining deadline). */
  timeoutMs?: number;
  /**
   * Total time budget for one forward, retries included. Stores time out webhook calls
   * (Pub/Sub push: 10 s ack deadline by default), so retrying past that is wasted work
   * that only holds memory and api capacity; better to answer 503 and let them redeliver.
   */
  deadlineMs?: number;
  /** Max concurrent requests to the api from this process (default 64). */
  maxConcurrent?: number;
  /** Max forwards waiting for a slot before shedding with 503 (default 1024). */
  maxQueue?: number;
  /** Consecutive failed attempts that open the circuit (default 10). */
  breakerThreshold?: number;
  /** Base open duration of the circuit (default 5 s, jittered ±20%). */
  breakerOpenMs?: number;
  fetchImpl?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
}

/**
 * Forwards entitlement events to the api with exponential backoff and full jitter,
 * bounded concurrency (bulkhead), a total deadline and a circuit breaker.
 * Retries only on 5xx, 429 and network/timeout errors; any other 4xx is permanent.
 */
export class HttpForwarder implements Forwarder {
  private readonly url: URL;
  private readonly maxAttempts: number;
  private readonly baseDelayMs: number;
  private readonly maxDelayMs: number;
  private readonly timeoutMs: number;
  private readonly deadlineMs: number;
  private readonly fetchImpl: typeof fetch;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly now: () => number;
  readonly bulkhead: Bulkhead;
  readonly breaker: CircuitBreaker;
  readonly stats: ForwarderStats = {
    attempts: { ok: 0, rejected: 0, retryable: 0, network: 0 },
    shed: { circuit_open: 0, overloaded: 0 },
  };

  constructor(private readonly opts: HttpForwarderOptions) {
    this.url = new URL('internal/v1/entitlements', withTrailingSlash(opts.apiUrl));
    this.maxAttempts = opts.maxAttempts ?? 5;
    this.baseDelayMs = opts.baseDelayMs ?? 200;
    this.maxDelayMs = opts.maxDelayMs ?? 5_000;
    this.timeoutMs = opts.timeoutMs ?? 3_000;
    this.deadlineMs = opts.deadlineMs ?? 8_000;
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.sleep = opts.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
    this.now = opts.now ?? Date.now;
    this.bulkhead = new Bulkhead({ maxConcurrent: opts.maxConcurrent ?? 64, maxQueue: opts.maxQueue ?? 1024 });
    this.breaker = new CircuitBreaker({
      failureThreshold: opts.breakerThreshold ?? 10,
      openMs: opts.breakerOpenMs ?? 5_000,
      now: this.now,
    });
  }

  async forward(event: EntitlementEvent): Promise<ForwardResult> {
    const body = JSON.stringify(event);
    const deadline = this.now() + this.deadlineMs;
    let lastError = 'unknown';
    let attempt = 0;

    while (attempt < this.maxAttempts) {
      const remaining = deadline - this.now();
      if (remaining <= 0) throw new ForwardUnavailableError(attempt, lastError, 'deadline');
      let outcome: AttemptOutcome;
      try {
        outcome = await this.bulkhead.run(() => this.attempt(body, Math.min(this.timeoutMs, remaining)), remaining);
      } catch (err) {
        if (err instanceof CircuitOpenError) {
          this.stats.shed.circuit_open++;
          throw new ForwardUnavailableError(attempt, lastError === 'unknown' ? 'circuit open' : lastError, 'circuit_open', err.retryAfterMs);
        }
        if (err instanceof BulkheadFullError) {
          this.stats.shed.overloaded++;
          throw new ForwardUnavailableError(attempt, err.message, 'overloaded', 1_000);
        }
        throw err;
      }
      attempt++;
      if (outcome.kind === 'ok') return outcome.result;
      if (outcome.kind === 'rejected') throw new ForwardRejectedError(outcome.status);
      lastError = outcome.error;
      if (attempt >= this.maxAttempts) break;
      const delay = this.backoff(attempt);
      // Do not start a retry that cannot finish inside the deadline.
      if (this.now() + delay >= deadline) throw new ForwardUnavailableError(attempt, lastError, 'deadline');
      await this.sleep(delay);
    }
    throw new ForwardUnavailableError(attempt, lastError, 'exhausted');
  }

  /** One HTTP attempt, inside a bulkhead slot and gated by the circuit breaker. */
  private async attempt(body: string, timeoutMs: number): Promise<AttemptOutcome> {
    this.breaker.admit(); // throws CircuitOpenError: no request is sent
    // Re-sign per attempt so a long backoff never pushes us outside the api's 300 s window.
    const headers = signRequest(this.opts.secret, 'POST', this.url.pathname, body, Math.floor(this.now() / 1000));
    try {
      const res = await this.fetchImpl(this.url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...headers },
        body,
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (res.ok) {
        const json = (await res.json().catch(() => ({}))) as Partial<ForwardResult>;
        this.breaker.success();
        this.stats.attempts.ok++;
        return { kind: 'ok', result: { applied: json.applied === true, ...(json.reason ? { reason: json.reason } : {}) } };
      }
      await res.body?.cancel().catch(() => undefined);
      if (res.status < 500 && res.status !== 429) {
        this.breaker.success(); // the api is up; it just refused this event
        this.stats.attempts.rejected++;
        return { kind: 'rejected', status: res.status };
      }
      this.breaker.failure();
      this.stats.attempts.retryable++;
      return { kind: 'retry', error: `HTTP ${res.status}` };
    } catch (err) {
      this.breaker.failure();
      this.stats.attempts.network++;
      return { kind: 'retry', error: err instanceof Error ? err.name + ': ' + err.message : String(err) };
    }
  }

  /** Full jitter: uniform in [0, min(max, base * 2^(attempt-1))]. */
  private backoff(attempt: number): number {
    const ceiling = Math.min(this.maxDelayMs, this.baseDelayMs * 2 ** (attempt - 1));
    return Math.floor(Math.random() * ceiling);
  }
}

type AttemptOutcome =
  | { kind: 'ok'; result: ForwardResult }
  | { kind: 'rejected'; status: number }
  | { kind: 'retry'; error: string };

function withTrailingSlash(u: URL): URL {
  const copy = new URL(u);
  if (!copy.pathname.endsWith('/')) copy.pathname += '/';
  copy.search = '';
  return copy;
}
