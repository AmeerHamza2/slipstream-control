/**
 * Small, dependency-free resilience primitives used on the path to the api.
 *
 * - `Bulkhead`: bounded concurrency with a bounded wait queue. Under a webhook burst it
 *   caps how many requests one replica sends to the api at once, and sheds load (fast
 *   503, the store redelivers) instead of growing an unbounded queue in memory.
 * - `CircuitBreaker`: after N consecutive failed attempts the api is considered down and
 *   calls fail fast for a (jittered) cool-down, then a single probe is let through.
 *   This keeps retries from piling up on an api that is already struggling.
 */

export class BulkheadFullError extends Error {
  constructor(readonly reason: 'queue_full' | 'queue_timeout') {
    super(reason === 'queue_full' ? 'too many requests waiting for the api' : 'timed out waiting for an api slot');
  }
}

export interface BulkheadOptions {
  maxConcurrent: number;
  maxQueue: number;
}

export class Bulkhead {
  private active = 0;
  private readonly waiters: Array<{ resolve: () => void; reject: (e: Error) => void; timer: NodeJS.Timeout | undefined }> = [];

  constructor(private readonly opts: BulkheadOptions) {
    if (opts.maxConcurrent < 1) throw new RangeError('maxConcurrent must be >= 1');
    if (opts.maxQueue < 0) throw new RangeError('maxQueue must be >= 0');
  }

  get inFlight(): number {
    return this.active;
  }
  get queued(): number {
    return this.waiters.length;
  }

  /** Runs `fn` once a slot is free. Waits at most `maxWaitMs` (and never if the queue is full). */
  async run<T>(fn: () => Promise<T>, maxWaitMs: number): Promise<T> {
    await this.acquire(maxWaitMs);
    try {
      return await fn();
    } finally {
      this.release();
    }
  }

  private acquire(maxWaitMs: number): Promise<void> {
    if (this.active < this.opts.maxConcurrent) {
      this.active++;
      return Promise.resolve();
    }
    if (this.waiters.length >= this.opts.maxQueue) return Promise.reject(new BulkheadFullError('queue_full'));
    if (maxWaitMs <= 0) return Promise.reject(new BulkheadFullError('queue_timeout'));
    return new Promise<void>((resolve, reject) => {
      const w = {
        resolve,
        reject,
        timer: setTimeout(() => {
          const i = this.waiters.indexOf(w);
          if (i >= 0) this.waiters.splice(i, 1);
          reject(new BulkheadFullError('queue_timeout'));
        }, maxWaitMs) as NodeJS.Timeout | undefined,
      };
      this.waiters.push(w);
    });
  }

  private release(): void {
    const next = this.waiters.shift();
    if (next) {
      // Hand the slot straight to the next waiter (active count unchanged).
      clearTimeout(next.timer);
      next.resolve();
    } else {
      this.active--;
    }
  }
}

export type BreakerState = 'closed' | 'open' | 'half_open';

export class CircuitOpenError extends Error {
  constructor(readonly retryAfterMs: number) {
    super('api circuit open');
  }
}

export interface CircuitBreakerOptions {
  /** Consecutive failed attempts that open the circuit. */
  failureThreshold: number;
  /** Base open duration; each opening is jittered by ±20% so replicas do not probe in lockstep. */
  openMs: number;
  now?: () => number;
  random?: () => number;
}

export class CircuitBreaker {
  private failures = 0;
  private openUntil = 0;
  private probing = false;
  private probeStartedAt = 0;
  private _state: BreakerState = 'closed';
  /** Number of times the circuit has opened (for metrics). */
  opened = 0;
  private readonly now: () => number;
  private readonly random: () => number;

  constructor(private readonly opts: CircuitBreakerOptions) {
    this.now = opts.now ?? Date.now;
    this.random = opts.random ?? Math.random;
  }

  get state(): BreakerState {
    if (this._state === 'open' && this.now() >= this.openUntil) this._state = 'half_open';
    return this._state;
  }

  /**
   * Call before an attempt. Throws CircuitOpenError while open, and while half-open
   * unless this caller is the single probe. Every admitted call must end in exactly one
   * `success()` or `failure()`.
   */
  admit(): void {
    const s = this.state;
    if (s === 'closed') return;
    // A probe that never reported back (should not happen) must not wedge the breaker.
    const probeLost = this.probing && this.now() - this.probeStartedAt > 2 * this.opts.openMs;
    if (s === 'half_open' && (!this.probing || probeLost)) {
      this.probing = true;
      this.probeStartedAt = this.now();
      return;
    }
    throw new CircuitOpenError(Math.max(1_000, this.openUntil - this.now()));
  }

  success(): void {
    this.failures = 0;
    this.probing = false;
    this._state = 'closed';
  }

  failure(): void {
    this.failures++;
    const s = this.state;
    if (s === 'half_open' || (s === 'closed' && this.failures >= this.opts.failureThreshold)) {
      this.probing = false;
      this._state = 'open';
      this.opened++;
      const jitter = 0.8 + 0.4 * this.random();
      this.openUntil = this.now() + Math.round(this.opts.openMs * jitter);
    }
  }

  /** Remaining open time, or 0 if not open. */
  retryAfterMs(): number {
    return this.state === 'open' ? Math.max(0, this.openUntil - this.now()) : 0;
  }
}
