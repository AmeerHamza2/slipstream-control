import { Redis } from 'ioredis';
import { AppleJwsVerifier } from './apple/jws.js';
import { CachingJwks, JwtUserVerifier, jwksUrl } from './auth/userJwt.js';
import { ConfigError, loadConfig } from './config.js';
import { HttpForwarder } from './forwarder.js';
import { type GooglePlayClient, HttpGooglePlayClient, UnconfiguredGooglePlayClient } from './google/client.js';
import { RedisIdempotencyStore } from './idempotency.js';
import { loggerOptions } from './logger.js';
import { Metrics } from './metrics.js';
import { EventPipeline } from './pipeline.js';
import { buildApp } from './server.js';

async function main(): Promise<void> {
  let config;
  try {
    config = loadConfig();
  } catch (err) {
    if (err instanceof ConfigError) {
      console.error(err.message);
      process.exit(2);
    }
    throw err;
  }

  const redis = new Redis(config.redisUrl, {
    // Fail fast instead of queueing: an unavailable Redis must not stall webhooks.
    enableOfflineQueue: false,
    maxRetriesPerRequest: 1,
    commandTimeout: 500,
    connectTimeout: 2_000,
  });
  const store = new RedisIdempotencyStore(redis, config.redisKeyPrefix);

  const google: GooglePlayClient = config.googleServiceAccountKeyPath
    ? HttpGooglePlayClient.fromFile(config.googleServiceAccountKeyPath)
    : new UnconfiguredGooglePlayClient();

  const forwarder = new HttpForwarder({
    apiUrl: config.apiUrl,
    secret: config.billingServiceSecret,
    maxConcurrent: config.apiMaxConcurrency,
    maxQueue: config.apiMaxQueue,
    deadlineMs: config.forwardDeadlineMs,
  });
  const pipeline = new EventPipeline(forwarder, store);
  const jwks = new CachingJwks(jwksUrl(config.apiUrl));
  const metrics = new Metrics();
  metrics.addCollector(() => forwarderMetrics(forwarder) + jwksMetrics(jwks) + redisMetrics(redis));
  const app = buildApp(
    {
      stripeWebhookSecret: config.stripeWebhookSecret,
      googlePushToken: config.googlePushToken,
      googlePackageName: config.googlePackageName,
      appleBundleId: config.appleBundleId,
      pipeline,
      apple: AppleJwsVerifier.fromFile(config.appleRootCaPath),
      google,
      users: new JwtUserVerifier(jwks.getKey),
      store,
      metrics,
    },
    loggerOptions(config.logLevel),
  );
  // ioredis emits 'error' on every reconnect attempt; log state changes, not every retry.
  let redisDown = false;
  redis.on('error', (err) => {
    if (!redisDown) app.log.warn({ err: err.message }, 'redis unavailable; idempotency checks fail open');
    redisDown = true;
  });
  redis.on('ready', () => {
    if (redisDown) app.log.info('redis available again');
    redisDown = false;
  });
  if (!config.googleServiceAccountKeyPath) app.log.warn('GOOGLE_SERVICE_ACCOUNT_KEY_PATH not set: Google lookups will 503');

  let shuttingDown = false;
  const shutdown = async (signal: string) => {
    if (shuttingDown) return;
    shuttingDown = true;
    app.log.info({ signal }, 'shutting down');
    const force = setTimeout(() => {
      app.log.error('graceful shutdown timed out');
      process.exit(1);
    }, config.shutdownTimeoutMs);
    force.unref();
    try {
      await app.close(); // stop accepting, wait for in-flight webhooks (and their forwards)
      await redis.quit().catch(() => redis.disconnect());
      process.exit(0);
    } catch (err) {
      app.log.error({ err }, 'error during shutdown');
      process.exit(1);
    }
  };
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));

  await app.listen({ port: config.port, host: config.host });
}

function forwarderMetrics(f: HttpForwarder): string {
  const state = f.breaker.state;
  return [
    '# TYPE billing_api_attempts_total counter',
    ...Object.entries(f.stats.attempts).map(([k, v]) => `billing_api_attempts_total{result="${k}"} ${v}`),
    '# TYPE billing_api_shed_total counter',
    ...Object.entries(f.stats.shed).map(([k, v]) => `billing_api_shed_total{reason="${k}"} ${v}`),
    '# TYPE billing_api_in_flight gauge',
    `billing_api_in_flight ${f.bulkhead.inFlight}`,
    '# TYPE billing_api_queued gauge',
    `billing_api_queued ${f.bulkhead.queued}`,
    '# TYPE billing_api_circuit_open gauge',
    `billing_api_circuit_open ${state === 'closed' ? 0 : 1}`,
    '# TYPE billing_api_circuit_opened_total counter',
    `billing_api_circuit_opened_total ${f.breaker.opened}`,
    '',
  ].join('\n');
}

function jwksMetrics(j: CachingJwks): string {
  return `# TYPE billing_jwks_fetches_total counter\nbilling_jwks_fetches_total ${j.fetches}\n` +
    `# TYPE billing_jwks_fetch_failures_total counter\nbilling_jwks_fetch_failures_total ${j.failures}\n`;
}

function redisMetrics(r: Redis): string {
  return `# TYPE billing_redis_up gauge\nbilling_redis_up ${r.status === 'ready' ? 1 : 0}`;
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
