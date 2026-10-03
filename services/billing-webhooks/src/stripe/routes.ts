import type { FastifyInstance } from 'fastify';
import { badRequest } from '../errors.js';
import { type RouteDeps, webhookAck } from '../http.js';
import { mapStripeEvent, type StripeEvent } from './mapping.js';
import { StripeSignatureError, verifyStripeSignature } from './signature.js';

export function registerStripeRoutes(app: FastifyInstance, deps: RouteDeps): void {
  app.post('/billing/stripe/webhook', async (req) => {
    try {
      verifyStripeSignature(
        req.rawBody ?? Buffer.alloc(0),
        req.headers['stripe-signature'] as string | undefined,
        deps.stripeWebhookSecret,
        Math.floor(deps.now() / 1000),
      );
    } catch (err) {
      if (err instanceof StripeSignatureError) {
        req.log.warn({ reason: err.message }, 'stripe signature rejected');
        throw badRequest('invalid Stripe signature');
      }
      throw err;
    }

    const event = req.body as Partial<StripeEvent> | undefined;
    if (!event || typeof event.id !== 'string' || typeof event.type !== 'string' ||
        typeof event.created !== 'number' || typeof event.data !== 'object' || event.data === null) {
      throw badRequest('not a Stripe event');
    }

    const mapped = mapStripeEvent(event as StripeEvent);
    if (mapped.kind === 'ignore') {
      req.log.info({ event_id: event.id, type: event.type, reason: mapped.reason }, 'stripe event ignored');
      return webhookAck({ ignored: mapped.reason });
    }
    return webhookAck(await deps.pipeline.process(mapped.event, req.log));
  });
}
