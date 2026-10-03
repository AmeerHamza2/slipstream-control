/**
 * Environment configuration. Validated once at startup; the process refuses to boot
 * with a missing or malformed value instead of failing on the first webhook.
 */
export interface Config {
  port: number;
  host: string;
  logLevel: string;
  apiUrl: URL;
  billingServiceSecret: string;
  stripeWebhookSecret: string;
  appleRootCaPath: string;
  /** If set, App Store payloads for any other bundle id are rejected. */
  appleBundleId: string | undefined;
  googlePushToken: string;
  /** If set, RTDNs for any other package are ignored. Required by the real Play client. */
  googlePackageName: string | undefined;
  /** Path to a Google service-account JSON key; without it Play lookups return 503. */
  googleServiceAccountKeyPath: string | undefined;
  redisUrl: string;
  redisKeyPrefix: string;
  /** Max concurrent requests from this replica to the api. */
  apiMaxConcurrency: number;
  /** Max forwards waiting for an api slot before shedding with 503. */
  apiMaxQueue: number;
  /** Total budget for one forward including retries. */
  forwardDeadlineMs: number;
  /** Hard limit for graceful shutdown. */
  shutdownTimeoutMs: number;
}

export class ConfigError extends Error {}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const problems: string[] = [];

  const required = (name: string, minLength = 1): string => {
    const v = env[name]?.trim();
    if (!v) {
      problems.push(`${name} is required`);
      return '';
    }
    if (v.length < minLength) problems.push(`${name} must be at least ${minLength} characters`);
    return v;
  };
  const optional = (name: string): string | undefined => env[name]?.trim() || undefined;

  const apiUrlRaw = required('API_URL');
  let apiUrl = new URL('http://invalid.local');
  if (apiUrlRaw) {
    try {
      apiUrl = new URL(apiUrlRaw);
      if (apiUrl.protocol !== 'http:' && apiUrl.protocol !== 'https:') {
        problems.push('API_URL must be http(s)');
      }
    } catch {
      problems.push('API_URL is not a valid URL');
    }
  }

  const portRaw = env.PORT?.trim() || '8081';
  const port = Number(portRaw);
  if (!Number.isInteger(port) || port < 1 || port > 65535) problems.push('PORT must be 1..65535');

  const int = (name: string, def: number, min: number, max: number): number => {
    const raw = env[name]?.trim();
    if (!raw) return def;
    const n = Number(raw);
    if (!Number.isInteger(n) || n < min || n > max) {
      problems.push(`${name} must be an integer in ${min}..${max}`);
      return def;
    }
    return n;
  };

  const redisUrl = required('REDIS_URL');
  if (redisUrl && !/^rediss?:\/\//.test(redisUrl)) problems.push('REDIS_URL must start with redis:// or rediss://');

  const cfg: Config = {
    port,
    host: env.HOST?.trim() || '0.0.0.0',
    logLevel: env.LOG_LEVEL?.trim() || 'info',
    apiUrl,
    // Shared HMAC secrets: insist on something that is plausibly random.
    billingServiceSecret: required('BILLING_SERVICE_SECRET', 16),
    stripeWebhookSecret: required('STRIPE_WEBHOOK_SECRET', 8),
    appleRootCaPath: required('APPLE_ROOT_CA_PATH'),
    appleBundleId: optional('APPLE_BUNDLE_ID'),
    googlePushToken: required('GOOGLE_PUSH_TOKEN', 16),
    googlePackageName: optional('GOOGLE_PACKAGE_NAME'),
    googleServiceAccountKeyPath: optional('GOOGLE_SERVICE_ACCOUNT_KEY_PATH'),
    redisUrl,
    redisKeyPrefix: env.REDIS_KEY_PREFIX?.trim() || 'billing:evt:',
    apiMaxConcurrency: int('API_MAX_CONCURRENCY', 64, 1, 4096),
    apiMaxQueue: int('API_MAX_QUEUE', 1024, 0, 100_000),
    forwardDeadlineMs: int('FORWARD_DEADLINE_MS', 8_000, 500, 60_000),
    shutdownTimeoutMs: int('SHUTDOWN_TIMEOUT_MS', 15_000, 1_000, 120_000),
  };
  if (cfg.forwardDeadlineMs + 2_000 > cfg.shutdownTimeoutMs) {
    problems.push('SHUTDOWN_TIMEOUT_MS must exceed FORWARD_DEADLINE_MS by at least 2000 so in-flight forwards can drain');
  }

  if (problems.length > 0) throw new ConfigError(`invalid configuration: ${problems.join('; ')}`);
  return cfg;
}
