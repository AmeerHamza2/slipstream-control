import type { Redis } from 'ioredis';

export const IDEMPOTENCY_TTL_SECONDS = 7 * 24 * 60 * 60;

/**
 * Remembers event ids that the api has already accepted. This is an optimisation that
 * short-circuits store redeliveries; the api's own idempotency on `event_id` is the
 * real guarantee, so a Redis outage degrades to "forward again", never to data loss.
 */
export interface IdempotencyStore {
  /** True if the event was already forwarded successfully. */
  isProcessed(eventId: string): Promise<boolean>;
  /** Record a successful forward (SET NX, TTL 7 days). */
  markProcessed(eventId: string): Promise<void>;
  ping(): Promise<boolean>;
}

/**
 * Redis is not connected. Thrown without touching the socket so that, during an outage,
 * each webhook pays nothing for the (failing-open) idempotency check; the connection
 * state change itself is logged once by main.ts.
 */
export class StoreUnavailableError extends Error {
  constructor() {
    super('idempotency store not connected');
  }
}

// One shared instance: capturing a stack per webhook during an outage is measurable CPU.
const NOT_CONNECTED = new StoreUnavailableError();

export class RedisIdempotencyStore implements IdempotencyStore {
  constructor(
    private readonly redis: Redis,
    private readonly prefix = 'billing:evt:',
    private readonly ttlSeconds = IDEMPOTENCY_TTL_SECONDS,
  ) {}

  async isProcessed(eventId: string): Promise<boolean> {
    this.assertReady();
    return (await this.redis.exists(this.prefix + eventId)) === 1;
  }

  async markProcessed(eventId: string): Promise<void> {
    this.assertReady();
    await this.redis.set(this.prefix + eventId, '1', 'EX', this.ttlSeconds, 'NX');
  }

  private assertReady(): void {
    if (this.redis.status !== 'ready') throw NOT_CONNECTED;
  }

  async ping(): Promise<boolean> {
    return (await this.redis.ping()) === 'PONG';
  }
}

/** In-memory implementation with the same semantics, for tests and local dev. */
export class MemoryIdempotencyStore implements IdempotencyStore {
  private readonly entries = new Map<string, number>();

  constructor(
    private readonly ttlSeconds = IDEMPOTENCY_TTL_SECONDS,
    private readonly now: () => number = Date.now,
  ) {}

  async isProcessed(eventId: string): Promise<boolean> {
    const exp = this.entries.get(eventId);
    if (exp === undefined) return false;
    if (exp <= this.now()) {
      this.entries.delete(eventId);
      return false;
    }
    return true;
  }

  async markProcessed(eventId: string): Promise<void> {
    if (await this.isProcessed(eventId)) return; // NX
    this.entries.set(eventId, this.now() + this.ttlSeconds * 1000);
  }

  async ping(): Promise<boolean> {
    return true;
  }
}
