# billing-webhooks

Node 22 + TypeScript + Fastify service that turns Stripe, App Store and Google Play
events into entitlement updates for the Go api (`POST /internal/v1/entitlements`,
see [`docs/CONTRACT.md`](../../docs/CONTRACT.md)). It holds no database: the api owns
entitlement state, ordering (`stale`) and idempotency (`duplicate`); this service
authenticates the stores, normalises their events and delivers them reliably.

```
Stripe ──Stripe-Signature──┐
App Store ──JWS + x5c──────┤   verify → map → [Redis: seen?] → sign HMAC → POST api → [Redis: SET NX]
Pub/Sub (Play RTDN) ─Bearer┤                                   (retry 5x, backoff+jitter)
App (receipt) ──user JWT───┘   2xx to the caller only after the api accepted the event
```

## Endpoints

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/billing/stripe/webhook` | `Stripe-Signature` | `checkout.session.completed`, `customer.subscription.updated/deleted`, `invoice.payment_failed` |
| POST | `/billing/apple/notifications` | Apple JWS (x5c → Apple Root CA G3) | App Store Server Notifications v2 `{signedPayload}` |
| POST | `/billing/google/rtdn` | `Authorization: Bearer $GOOGLE_PUSH_TOKEN` | Pub/Sub push; purchase looked up via `GooglePlayClient` |
| POST | `/billing/apple/verify` | user JWT | `{signed_transaction}`; requires `appAccountToken == sub` |
| POST | `/billing/google/verify` | user JWT | `{purchase_token, product_id}`; requires `obfuscatedExternalAccountId == sub` |
| GET | `/healthz` | none | liveness; reports Redis state without failing on it |

Webhook responses: `200 {"received":true,"applied":bool}`, `{"received":true,"duplicate":true}`
or `{"received":true,"ignored":"<reason>"}`. Client verify responses:
`200 {"status","expires_at","applied"}`. Errors use the contract shape
`{"error":{"code","message","request_id"}}`, and every response carries `X-Request-Id`.

## Flows and mapping

**Stripe.** The signature is checked by hand (no SDK, so the logic is visible): parse `t=` and
every `v1=`, compute `HMAC-SHA256(secret, t + "." + rawBody)` over the **raw bytes** (a custom
content-type parser keeps the `Buffer`), compare in constant time against each candidate
(several `v1` appear during secret rotation), then enforce `|now - t| <= 300 s`.

| Event | Status | `expires_at` |
|---|---|---|
| `checkout.session.completed` | `active` | expanded subscription's period end, else a provisional `created + 48h` |
| `customer.subscription.updated` | `active`/`trialing` → `active`, `past_due` → `grace`, `canceled`/`unpaid`/`incomplete_expired`/`paused` → `expired` (`incomplete` ignored) | period end (`ended_at` when expired) |
| `customer.subscription.deleted` | `expired` | `ended_at` / `canceled_at` |
| `invoice.payment_failed` | `grace` | `next_payment_attempt` (or now, when no retry is left) |

`user_id` comes from `client_reference_id`, then `metadata.user_id` (the checkout must set
`subscription_data.metadata.user_id` so later subscription and invoice events carry it).
`original_transaction_id` is the subscription id, `occurred_at` is `event.created`, and
`event_id` is the Stripe event id. Both the old and the 2025+ ("basil") payload shapes are read.

**App Store.** Apple JWS headers carry `x5c = [leaf, WWDR intermediate, root]`. `AppleJwsVerifier`:
1. requires `alg = ES256` and 2–3 certificates;
2. checks the validity window of every certificate, including the pinned root;
3. for each link, runs `child.checkIssued(issuer) && child.verify(issuer.publicKey)` with
   `node:crypto` `X509Certificate`, and requires each issuer to be a CA;
4. requires the chain to end at the root loaded from `APPLE_ROOT_CA_PATH`: either the same
   bytes, or signed by it. An attacker's chain with Apple's root appended fails at step 3;
5. requires Apple's marker extensions, which is what Apple's own server library checks:
   **`1.2.840.113635.100.6.11.1`** on the leaf ("Mac App Store Receipt Signing") and
   `1.2.840.113635.100.6.2.1` on the intermediate (WWDR). Without them, *any* certificate
   Apple ever issued under Root CA G3, a developer's own signing certificate for example,
   could sign a "valid" transaction. Node does not expose arbitrary extensions, so
   `src/apple/der.ts` walks the DER (about 60 lines, no dependency);
6. verifies the JWS with the leaf key (`jose.compactVerify`, `algorithms: ['ES256']`).

The nested `signedTransactionInfo` and `signedRenewalInfo` are separate JWS and go through
the same verification. If `APPLE_BUNDLE_ID` is set, payloads for other bundles are rejected.

| notificationType | Status | `expires_at` |
|---|---|---|
| `SUBSCRIBED`, `DID_RENEW`, `OFFER_REDEEMED` | `active` | `expiresDate` |
| `DID_FAIL_TO_RENEW` | `grace` | `gracePeriodExpiresDate` (subtype `GRACE_PERIOD`), else `expiresDate` (billing retry; already past, so not active) |
| `EXPIRED`, `GRACE_PERIOD_EXPIRED` | `expired` | `expiresDate` |
| `REFUND` / `REVOKE` | `refunded` / `revoked` | `revocationDate` |
| anything else (`DID_CHANGE_RENEWAL_STATUS`, `TEST`, …) | acknowledged, not forwarded | |

`user_id` is `appAccountToken`, which the app sets to the user id at purchase.
`event_id` is `notificationUUID`, `occurred_at` is `signedDate`, and
`original_transaction_id` is `originalTransactionId`.

**Google Play.** The Pub/Sub push must carry `Authorization: Bearer <GOOGLE_PUSH_TOKEN>`. Both
values are SHA-256 hashed and then compared with `timingSafeEqual`, so neither the token
nor its length leaks through timing. `message.data` is base64 JSON. RTDNs do not carry
expiry or account, so the purchase is fetched through `GooglePlayClient.getSubscription`
(androidpublisher v3 `purchases.subscriptionsv2.get`).

| notificationType | Status |
|---|---|
| `PURCHASED` (4), `RENEWED` (2), `RECOVERED` (1), `RESTARTED` (7) | `active` |
| `IN_GRACE_PERIOD` (6) | `grace` |
| `ON_HOLD` (5), `PAUSED` (10), `EXPIRED` (13) | `expired` |
| `REVOKED` (12) | `revoked` |
| `CANCELED` (3), `DEFERRED` (9) | derived: `active` while `expiryTime` is in the future, else `expired` |
| `voidedPurchaseNotification` (subscription) | `refunded` |

`user_id` is `externalAccountIdentifiers.obfuscatedExternalAccountId` (the app passes the user
id to `BillingFlowParams.setObfuscatedAccountId`). `event_id` is the Pub/Sub `messageId` and
`occurred_at` is `eventTimeMillis`. Active purchases still pending acknowledgement are
acknowledged after a successful forward, because Google refunds subscriptions left
unacknowledged for 3 days. `HttpGooglePlayClient` signs a service-account JWT (RS256),
exchanges it for an OAuth2 token (cached until 60 s before expiry, concurrent refreshes
coalesced) and calls the REST API directly. Tests use `FakeGooglePlay`.

**Client verify.** User access tokens are verified locally against `API_URL/.well-known/jwks.json`
(`CachingJwks` in `src/auth/userJwt.ts`): 5-minute cache refreshed in the background while
the old keys keep serving (stale-while-revalidate, up to 1 h if the api is down), one fetch at
a time, failures negatively cached for 5 s so a down api is not hit by every request, a 30 s
cooldown on unknown-`kid` refetches, and fetch failures answered `503` (never a misleading
`401`, which would log the app out). `algorithms: ['EdDSA']` pinned, plus `iss=slipstream-control`, `aud=slipstream-app` and a UUID `sub`. The purchase
must be bound to that `sub` (otherwise `403`), so a receipt bought on one account cannot
unlock another. Without a store-provided id, `event_id` is derived:
`app_store:<transactionId>:<status>` and `google_play:<token hash>:<status>:<expiry>`. A
resubmitted receipt is then a duplicate, while a refund or renewal is a new event.

## Delivery guarantees

- **Forwarding** (`src/forwarder.ts`): every request is HMAC-signed per the contract and
  re-signed on each attempt, so a long backoff never falls outside the api's 300 s window.
  Up to 5 attempts, full-jitter exponential backoff (200 ms base, 5 s cap), 3 s per-attempt
  timeout, and an 8 s **total deadline** (`FORWARD_DEADLINE_MS`) so a forward never outlives
  the store's own webhook timeout (Pub/Sub's default ack deadline is 10 s). 5xx, 429 and
  network errors are retried; any other 4xx is permanent.
- **Bounded concurrency** (`src/resilience.ts`, `Bulkhead`): at most `API_MAX_CONCURRENCY`
  (64) requests from one replica to the api at once, with at most `API_MAX_QUEUE` (1024)
  waiting. Beyond that the webhook is shed immediately with `503` + `Retry-After` and the
  store redelivers, so a burst cannot grow memory without bound or pile onto the api.
- **Circuit breaker** (`CircuitBreaker`): 10 consecutive failed attempts open the circuit
  for 5 s (±20% jitter so replicas do not probe in lockstep); while open, forwards fail
  fast with `503` + `Retry-After` and send nothing; then a single probe request decides.
  Retries therefore stop hammering an api that is already down.
- **Answering the store**: 2xx only once the api returned 200 (`applied` true or false).
  `503` + `Retry-After` when the api is unavailable (retries exhausted, deadline, circuit
  open, load shed); `502` when it permanently rejected the event (4xx, e.g. a rotated
  secret or clock skew, which heals once fixed). Stripe, Apple and Pub/Sub redeliver both.
- **Idempotency**: `EXISTS` before forwarding (a duplicate short-circuits to `200`), and
  `SET key 1 EX 604800 NX` only **after** the api accepted, so a failed forward is never
  remembered. Redis is an optimisation, not the source of truth (the api is idempotent on
  `event_id`). Redis errors therefore **fail open**: we forward again rather than drop a
  payment event. The ioredis client runs with no offline queue and a 500 ms command timeout,
  and while it is disconnected the store skips Redis entirely (no socket write, no
  per-event log line; the state change is logged once), so an outage cannot stall webhooks.
- **Permanent problems** (unhandled type, no user binding, unknown token, test
  notification) are acknowledged with `200 {"ignored": ...}` and logged, so the store does
  not retry forever.

## Security notes

- Logs are pino JSON. Requests serialise to method and path only (no headers, query,
  remote address or body), and sensitive keys are redacted. Logs never contain receipts,
  JWS, purchase tokens, tokens or IPs, only event ids and user ids (allowed by the contract).
- Purchase tokens are never forwarded raw: `original_transaction_id` for Google is
  `gp_` + SHA-256(token), which stays stable across renewals.
- `X-Request-Id` is echoed only if it matches `[A-Za-z0-9._:-]{1,128}`, to prevent log injection.
- Body limit is 256 KiB (413 before any parsing or verification). JWS inputs are capped at 64 KiB.
- HTTP server limits: 15 s to receive a whole request and 10 s for its headers (slowloris
  guard), 72 s keep-alive (longer than common load-balancer idle timeouts, so the LB closes
  first and never reuses a socket we just closed).
- Not implemented (deliberately, documented): Apple OCSP revocation checks, Pub/Sub OIDC
  push authentication (the contract specifies a shared bearer token), and an
  `environment` (Sandbox/Production) filter.

## Configuration

| Var | Required | Notes |
|---|---|---|
| `API_URL` | yes | e.g. `http://api:8080`; JWKS and `/internal/v1/entitlements` are resolved against it |
| `BILLING_SERVICE_SECRET` | yes | ≥ 16 chars, shared with the api |
| `STRIPE_WEBHOOK_SECRET` | yes | `whsec_…` |
| `APPLE_ROOT_CA_PATH` | yes | PEM or DER, from <https://www.apple.com/certificateauthority/AppleRootCA-G3.cer> |
| `GOOGLE_PUSH_TOKEN` | yes | ≥ 16 chars; set the same token on the Pub/Sub push endpoint |
| `REDIS_URL` | yes | `redis://` or `rediss://` |
| `PORT` | no | default `8081` (`HOST` default `0.0.0.0`) |
| `APPLE_BUNDLE_ID` | no | reject other bundles |
| `GOOGLE_PACKAGE_NAME` | for Google verify | RTDNs for other packages are ignored |
| `GOOGLE_SERVICE_ACCOUNT_KEY_PATH` | for Google | without it Google lookups return 503 (retryable) |
| `REDIS_KEY_PREFIX`, `LOG_LEVEL` | no | defaults `billing:evt:`, `info` |
| `API_MAX_CONCURRENCY` / `API_MAX_QUEUE` | no | per replica, defaults `64` / `1024` |
| `FORWARD_DEADLINE_MS` | no | default `8000`, total budget for one forward incl. retries |
| `SHUTDOWN_TIMEOUT_MS` | no | default `15000`; must exceed the forward deadline by 2 s |

The process validates everything at boot and exits with code 2, listing every problem at once.
On SIGTERM/SIGINT it stops accepting connections, answers `503` on kept-alive ones, closes
idle ones, waits for in-flight webhooks (and their forwards, bounded by the 8 s deadline)
and closes Redis, with a 15 s hard timeout. Give the container a longer stop grace period
than that (compose: `stop_grace_period: 20s`; Docker's default is 10 s).

## Metrics (`GET /metrics`)

Prometheus text, no extra dependency: `billing_http_responses_total{route,status}` and
`billing_http_response_seconds_sum{route,status}`, `billing_api_attempts_total{result}`
(`ok`, `rejected`, `retryable`, `network`), `billing_api_shed_total{reason}` (`circuit_open`,
`overloaded`), `billing_api_in_flight`, `billing_api_queued`, `billing_api_circuit_open`,
`billing_api_circuit_opened_total`, `billing_jwks_fetches_total`,
`billing_jwks_fetch_failures_total`, `billing_redis_up`. Labels are route patterns and status
codes only, so cardinality is fixed.

## Scale & robustness

**Horizontal scaling.** Replicas share nothing that matters: idempotency lives in Redis, the
api is the source of truth (idempotent on `event_id`, order-safe), and what is per process
(circuit state, JWKS and Google token caches, the bulkhead) is a cache or a local limit. Two
replicas receiving the same redelivery at the same moment may both forward it; the api answers
the second with `duplicate`. Note that the api sees up to `replicas × API_MAX_CONCURRENCY`
concurrent requests from this service.

**Load test** (`npm run loadtest` or `npx tsx scripts/loadtest.ts [scenario...]`; Redis DB from
`REDIS_URL`, default `/7`). It runs the built service as a child process against a fake api
(15 ms ± 50% latency, verifies the HMAC independently, counts applications per `event_id`)
and acts as a store: non-2xx answers are redelivered with backoff, and 5-10% of acknowledged
events are redelivered as duplicates. Measured on a shared 2-vCPU sandbox that was also
running another heavy workload, so absolute latency is pessimistic:

| Scenario | Result |
|---|---|
| Renewal storm, 5,000 webhooks/min for 30 s (+10% duplicates) | 92 req/s, p50 19 ms, p99 65 ms, 0 lost, 0 duplicate api calls (all redeliveries short-circuited by Redis), RSS 131 MB |
| Max throughput, 20,000 events, 256 concurrent senders | ~970 req/s (CPU-bound: ~0.75 ms CPU per webhook, so one core is ~1,300/s), p50 230 ms, p99 690 ms, api concurrency capped at 64, 0 lost, RSS 244 MB |
| api down for 4 s mid-burst (2,000/s) | circuit opened: only 73 requests reached the down api; 2,078 fast `503`s; every event applied after recovery, 0 lost, 0 acknowledged-but-not-applied |
| Redis unreachable (500/s) | fail-open, all 200; the 10% duplicate redeliveries reach the api (which dedups); 0 lost |
| SIGTERM mid-burst (api latency 100 ms) | in-flight webhooks drained, exit 0 in < 1 s; refused requests redelivered to a new replica; 0 lost |

Memory stays flat after warm-up (no per-event state in process; the bulkhead queue is
bounded). In the outage scenarios latencies early in a run are higher while 128-256 new
connections ramp up on the contended host; steady-state numbers are above.


## Run

```sh
npm ci
npm test                      # unit + route tests (fakes); add REDIS_URL=redis://127.0.0.1:6379 for the Redis integration test
npm run lint                  # tsc --noEmit (src + test)
npm run build && npm start    # needs the env above

docker build -t slipstream/billing-webhooks .
docker run -p 8081:8081 --env-file .env \
  -v $PWD/AppleRootCA-G3.cer:/etc/slipstream/AppleRootCA-G3.cer:ro slipstream/billing-webhooks
```

The tests generate their own PKI with `@peculiar/x509`: a root CA, a WWDR-like intermediate
and a leaf carrying the receipt-signing OID. This exercises the real chain code, including
rejections for a wrong root, a spliced chain, an expired leaf, missing OIDs, a non-CA
intermediate, a wrong signing key, a tampered payload and `alg: none`. A fake api verifies
the service HMAC with an independent implementation. A local JWKS server issues Ed25519
tokens the way the Go api does.

## Layout

```
src/
  main.ts            wiring, Redis, graceful shutdown
  server.ts          Fastify app: raw-body JSON parser, request ids, error shape, /healthz
  config.ts          env validation
  pipeline.ts        dedupe → forward → remember
  forwarder.ts       contract HMAC signing + retrying HTTP forwarder (deadline, bulkhead, breaker)
  resilience.ts      Bulkhead (bounded concurrency + queue) and CircuitBreaker
  metrics.ts         Prometheus text exposition
  idempotency.ts     IdempotencyStore (Redis SET NX EX, in-memory fake)
  auth/userJwt.ts    EdDSA JWT via a caching, failure-tolerant JWKS
  stripe/            signature.ts, mapping.ts, routes.ts
  apple/             der.ts (extension OIDs), jws.ts (chain + ES256), mapping.ts, routes.ts
  google/            client.ts (interface + androidpublisher impl), mapping.ts, routes.ts
test/                node:test suites + helpers (PKI, fake api, JWKS server, fake Play client)
scripts/loadtest.ts  burst / outage / shutdown load test against the built service
```
