import type { AppleJwsVerifier } from './apple/jws.js';
import type { UserVerifier } from './auth/userJwt.js';
import type { GooglePlayClient } from './google/client.js';
import type { IdempotencyStore } from './idempotency.js';
import type { Metrics } from './metrics.js';
import type { EventPipeline, PipelineOutcome } from './pipeline.js';

export interface AppDeps {
  stripeWebhookSecret: string;
  googlePushToken: string;
  googlePackageName?: string | undefined;
  appleBundleId?: string | undefined;
  pipeline: EventPipeline;
  apple: AppleJwsVerifier;
  google: GooglePlayClient;
  users: UserVerifier;
  store: IdempotencyStore;
  /** If set, request metrics are recorded and served at GET /metrics. */
  metrics?: Metrics;
  now?: () => number;
}

export type RouteDeps = AppDeps & { now: () => number };

export function errorBody(code: string, message: string, requestId: string) {
  return { error: { code, message, request_id: requestId } };
}

/** Body returned to Stripe / Apple / Pub/Sub. Anything 2xx means "do not redeliver". */
export function webhookAck(outcome: PipelineOutcome | { ignored: string }) {
  if ('ignored' in outcome) return { received: true, ignored: outcome.ignored };
  if (outcome.outcome === 'duplicate') return { received: true, duplicate: true };
  return { received: true, applied: outcome.result.applied, ...(outcome.result.reason ? { reason: outcome.result.reason } : {}) };
}
