import type { FastifyBaseLogger } from 'fastify';
import type { EntitlementEvent } from './entitlement.js';
import { upstream } from './errors.js';
import { ForwardRejectedError, ForwardUnavailableError, type Forwarder, type ForwardResult } from './forwarder.js';
import { StoreUnavailableError, type IdempotencyStore } from './idempotency.js';

export type PipelineOutcome =
  | { outcome: 'duplicate' }
  | { outcome: 'forwarded'; result: ForwardResult };

/**
 * duplicate check -> forward (with retries) -> remember.
 *
 * Throws an HttpError when the api did not accept the event, so the webhook is answered
 * non-2xx and the store / Stripe / Pub/Sub redelivers later: 503 + Retry-After when the
 * api is unavailable (retries exhausted, deadline, circuit open, load shed), 502 when it
 * permanently rejected the event (4xx, e.g. a rotated secret; heals once fixed).
 */
export class EventPipeline {
  constructor(
    private readonly forwarder: Forwarder,
    private readonly store: IdempotencyStore,
  ) {}

  /** `log` is the request logger, so every line carries the request id. */
  async process(event: EntitlementEvent, log: FastifyBaseLogger): Promise<PipelineOutcome> {
    const ctx = { event_id: event.event_id, source: event.source, status: event.status, user_id: event.user_id };

    try {
      if (await this.store.isProcessed(event.event_id)) {
        log.info(ctx, 'duplicate delivery short-circuited');
        return { outcome: 'duplicate' };
      }
    } catch (err) {
      // Fail open: the api is idempotent on event_id, so forwarding twice is safe.
      // A disconnected Redis is logged once by main.ts; per-event lines would flood logs.
      log[err instanceof StoreUnavailableError ? 'debug' : 'warn']({ ...ctx, err: errMessage(err) }, 'idempotency check failed; forwarding anyway');
    }

    let result: ForwardResult;
    try {
      result = await this.forwarder.forward(event);
    } catch (err) {
      if (err instanceof ForwardRejectedError) {
        log.error({ ...ctx, api_status: err.status }, 'api rejected entitlement event');
        throw upstream(502, 'entitlement could not be applied; retry later');
      }
      if (err instanceof ForwardUnavailableError) {
        // Shed requests are expected during an outage/burst: keep them at warn, one line each.
        const level = err.reason === 'exhausted' || err.reason === 'deadline' ? 'error' : 'warn';
        log[level]({ ...ctx, reason: err.reason, attempts: err.attempts, err: err.lastError }, 'api unavailable; event not accepted');
        throw upstream(503, 'entitlement could not be applied; retry later', Math.max(1, Math.ceil(err.retryAfterMs / 1000)));
      }
      log.error({ ...ctx, err: errMessage(err) }, 'api unavailable; event not accepted');
      throw upstream(503, 'entitlement could not be applied; retry later', 1);
    }

    // Only remember the event after the api accepted it (applied, duplicate or stale).
    try {
      await this.store.markProcessed(event.event_id);
    } catch (err) {
      log[err instanceof StoreUnavailableError ? 'debug' : 'warn']({ ...ctx, err: errMessage(err) }, 'failed to record processed event');
    }
    log.info({ ...ctx, applied: result.applied, reason: result.reason }, 'entitlement forwarded');
    return { outcome: 'forwarded', result };
  }
}

export const errMessage = (err: unknown): string => (err instanceof Error ? err.message : String(err));
