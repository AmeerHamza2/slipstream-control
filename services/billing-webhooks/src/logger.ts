import type { FastifyServerOptions } from 'fastify';

/**
 * pino options. The contract forbids emails, tokens, keys, IPs and receipts in logs, so
 * requests are serialised to method + path only (no headers, query string, remote
 * address or body), and anything that slips into a log object under a sensitive key
 * is redacted.
 */
export function loggerOptions(level: string): FastifyServerOptions['logger'] {
  return {
    level,
    base: { service: 'billing-webhooks' },
    timestamp: () => `,"time":"${new Date().toISOString()}"`,
    serializers: {
      req: (req: { method?: string; url?: string }) => ({ method: req.method, path: req.url?.split('?')[0] }),
      res: (res: { statusCode?: number }) => ({ status: res.statusCode }),
    },
    redact: {
      paths: [
        'authorization', '*.authorization', 'headers', '*.headers',
        'signedPayload', 'signed_transaction', 'purchase_token', 'purchaseToken', 'token', 'email',
      ],
      censor: '[redacted]',
    },
  };
}
