import { randomUUID } from 'node:crypto';
import Fastify, { LogController, type FastifyInstance, type FastifyServerOptions } from 'fastify';
import { registerAppleRoutes } from './apple/routes.js';
import { HttpError } from './errors.js';
import { errorBody, type AppDeps, type RouteDeps } from './http.js';
import { registerGoogleRoutes } from './google/routes.js';
import { registerStripeRoutes } from './stripe/routes.js';

export type { AppDeps } from './http.js';

declare module 'fastify' {
  interface FastifyRequest {
    /** Exact request bytes; Stripe signs these, not the parsed JSON. */
    rawBody?: Buffer;
  }
}

const REQUEST_ID_RE = /^[A-Za-z0-9._:-]{1,128}$/;

/** HTTP server limits. Defaults suit a service behind a load balancer with a 60 s idle timeout. */
export interface ServerLimits {
  /** Max request body (default 256 KiB; store payloads are a few KiB). */
  bodyLimit?: number;
  /** Max time to receive a whole request, headers + body (default 15 s; slowloris guard). */
  requestTimeoutMs?: number;
  /** Idle keep-alive timeout (default 72 s: longer than common LB idle timeouts, so the LB closes first). */
  keepAliveTimeoutMs?: number;
  /** Socket inactivity timeout (default 0 = governed by the two above). */
  connectionTimeoutMs?: number;
}

export function buildApp(
  deps: AppDeps,
  logger: FastifyServerOptions['logger'] = false,
  limits: ServerLimits = {},
): FastifyInstance {
  const app = Fastify({
    logger,
    bodyLimit: limits.bodyLimit ?? 256 * 1024,
    requestTimeout: limits.requestTimeoutMs ?? 15_000,
    keepAliveTimeout: limits.keepAliveTimeoutMs ?? 72_000,
    connectionTimeout: limits.connectionTimeoutMs ?? 0,
    // While closing, answer 503 on kept-alive connections (stores redeliver) and close idle ones.
    return503OnClosing: true,
    forceCloseConnections: 'idle',
    requestIdHeader: false,
    // Echo a well-formed X-Request-Id, otherwise mint one (never trust arbitrary bytes into logs).
    genReqId: (req) => {
      const h = req.headers['x-request-id'];
      return typeof h === 'string' && REQUEST_ID_RE.test(h) ? h : randomUUID();
    },
    logController: new LogController({ requestIdLogLabel: 'request_id' }),
  });
  // Headers must arrive well inside the request timeout (Node's default is 60 s).
  app.server.headersTimeout = Math.min(10_000, limits.requestTimeoutMs ?? 15_000);
  const routeDeps: RouteDeps = { ...deps, now: deps.now ?? Date.now };

  // Keep the raw bytes for signature verification, then parse.
  app.addContentTypeParser('application/json', { parseAs: 'buffer' }, (req, body, done) => {
    const buf = body as Buffer;
    req.rawBody = buf;
    try {
      done(null, buf.length === 0 ? {} : JSON.parse(buf.toString('utf8')));
    } catch {
      done(new HttpError(400, 'invalid_request', 'body is not valid JSON'), undefined);
    }
  });

  app.addHook('onSend', async (req, reply) => {
    reply.header('X-Request-Id', req.id);
  });

  const metrics = deps.metrics;
  if (metrics) {
    app.addHook('onResponse', async (req, reply) => {
      metrics.observe(req.routeOptions.url ?? 'unmatched', reply.statusCode, reply.elapsedTime / 1000);
    });
    app.get('/metrics', async (_req, reply) => {
      reply.header('Content-Type', 'text/plain; version=0.0.4');
      return metrics.render();
    });
  }

  app.setErrorHandler((err, req, reply) => {
    if (err instanceof HttpError) {
      if (err.statusCode >= 500) req.log.warn({ code: err.code, msg_detail: err.message }, 'request failed');
      if (err.retryAfterS !== undefined) reply.header('Retry-After', String(err.retryAfterS));
      return reply.status(err.statusCode).send(errorBody(err.code, err.message, req.id));
    }
    const status = (err as { statusCode?: number }).statusCode;
    if (status && status >= 400 && status < 500) {
      return reply.status(status).send(errorBody('invalid_request', (err as Error).message, req.id));
    }
    req.log.error({ err }, 'unhandled error');
    return reply.status(500).send(errorBody('internal', 'internal error', req.id));
  });

  app.setNotFoundHandler((req, reply) => {
    reply.status(404).send(errorBody('not_found', 'route not found', req.id));
  });

  // Liveness only: Redis is an optimisation (see idempotency.ts), so its state is
  // reported but never makes the process look dead.
  app.get('/healthz', async () => {
    const redis = await deps.store.ping().catch(() => false);
    return { status: 'ok', redis: redis ? 'up' : 'down' };
  });

  registerStripeRoutes(app, routeDeps);
  registerAppleRoutes(app, routeDeps);
  registerGoogleRoutes(app, routeDeps);
  return app;
}
