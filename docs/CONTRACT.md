# Slipstream Control: service contract

This is the source of truth the three services are built against. Any change here is
a breaking change for at least one of them.

```
               ┌────────────── Slipstream VPN app (TunnelCore engine) ─────────────┐
               │ signup/login · register device pubkey · fetch config · purchase   │
               └──────────────┬───────────────────────────────┬────────────────────┘
                     JWT (EdDSA) │                              │ receipt / purchase
                                ▼                              ▼
┌──────────────────────────────────────────┐   ┌─────────────────────────────────────┐
│ api  (Go, :8080)                          │◄──│ billing-webhooks (Node, :8081)       │
│ accounts · devices · WireGuard IPAM ·     │   │ Stripe / App Store / Google Play     │
│ server selection · config issuance ·      │   │ webhooks + client receipt verify →   │
│ entitlements · rate limiting · OpenAPI    │   │ POST /internal/v1/entitlements       │
└───────┬──────────────────────▲────────────┘   └─────────────────────────────────────┘
        │ Postgres · Redis     │ POST /internal/v1/servers/heartbeats
        ▼                      │
                     ┌─────────┴────────────────────────┐
                     │ fleet-prober (Python)             │
                     │ probes every server (UDP/TCP RTT, │
                     │ loss) → health + load reports     │
                     └───────────────────────────────────┘
```

## Shared conventions

- JSON everywhere, `snake_case` fields, RFC 3339 UTC timestamps, UUIDv4 ids as strings.
- Errors: `{"error": {"code": "snake_case_code", "message": "human text", "request_id": "..."}}`.
  Codes are `invalid_request`, `unauthorized`, `forbidden`, `not_found`, `conflict`,
  `rate_limited`, `payment_required`, `internal`.
- Every response carries `X-Request-Id`, echoed from the request if present and otherwise generated.
- Transient failures are `503` + `Retry-After` with code `internal`, never `500`: Postgres
  unreachable or slow, password-hashing capacity saturated, rate limiter down on auth
  endpoints, no healthy servers, tunnel address pool exhausted. Callers retry with backoff.
  (A `500` means a bug.)
- Logs are structured JSON, and never contain emails, passwords, tokens, keys, IP addresses or
  receipts. User ids are allowed.

## Authentication

### User tokens (app → api, verified by billing-webhooks too)
- Access token: JWT signed **EdDSA (Ed25519)**, `kid` header, 15 min TTL.
  Claims: `iss=slipstream-control`, `aud=slipstream-app`, `sub=<user_id>`, `exp`, `iat`, `jti`.
- Refresh token: opaque 32-byte random value, base64url. Only its SHA-256 is stored in the DB.
  It rotates on every use, and **reuse of a rotated token revokes the whole token family**.
- Public keys are published at `GET /.well-known/jwks.json` (RFC 8037 OKP, `crv=Ed25519`).
  billing-webhooks verifies user tokens locally against this JWKS and caches it for 5 minutes.

### Service-to-service (billing-webhooks → api, fleet-prober → api)
HMAC-SHA256 request signing with a shared secret per caller:

```
X-Slipstream-Service:   billing-webhooks | fleet-prober
X-Slipstream-Timestamp: <unix seconds>
X-Slipstream-Signature: v1=<hex(HMAC_SHA256(secret, timestamp + "." + METHOD + "." + path + "." + body))>
```
- `path` is the URL path without the query string, e.g. `/internal/v1/entitlements`.
- The api rejects requests more than 300 s from its clock, and compares signatures in constant time.
- Secrets come from env vars: `BILLING_SERVICE_SECRET` and `PROBER_SERVICE_SECRET`
  (each caller has its own; the api knows both).

## Public API (api, `/v1`), app-facing

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/v1/auth/signup` | none | `{email, password}` → 201 `{user_id}`. Password ≥ 12 chars, argon2id |
| POST | `/v1/auth/login` | none | `{email, password}` → `{access_token, refresh_token, expires_in}` |
| POST | `/v1/auth/refresh` | none | `{refresh_token}` → new pair (rotation) |
| POST | `/v1/auth/logout` | user | revoke the current refresh family |
| GET | `/v1/me` | user | `{user_id, email, plan, entitlement: {active, expires_at, source}, devices_used, devices_limit}` |
| GET | `/v1/servers` | user | public server list: `[{id, name, country, city, protocols, load, healthy}]`, no secrets. Served from a per-replica snapshot at most `SERVER_CACHE_TTL` (default 2 s) old; `ETag` / `If-None-Match` (304) and gzip supported |
| POST | `/v1/devices` | user | `{name, platform: "android"|"ios", wg_public_key}` → 201 `{device_id, tunnel_address}` |
| GET | `/v1/devices` | user | list the user's devices |
| DELETE | `/v1/devices/{id}` | user | remove a device and free its address |
| POST | `/v1/devices/{id}/config` | user + active entitlement | `{country?: "DE"}` → TunnelCore config JSON (see below). 402 `payment_required` without an entitlement |
| GET | `/healthz`, `/readyz` | none | liveness and readiness (DB + Redis) |
| GET | `/metrics` | none | Prometheus text format |
| GET | `/openapi.yaml` | none | the spec |

Rate limits (Redis, sliding window): signup/login 10/min per client IP plus 5/min per
email hash; everything else 120/min per user. A 429 comes with `Retry-After`. If Redis is
down, auth endpoints fail **closed** and the rest fail open, with a metric counting it.

Device limit: plan `free` = 0 devices (cannot connect), `premium` = 5.

### Config issuance (`POST /v1/devices/{id}/config`)
Returns exactly the TunnelCore contract (see the tunnelcore README), minus the private key:

```json
{
  "servers": [
    {"name": "fra-01", "protocol": "wireguard", "endpoint": "203.0.113.10:51820",
     "public_key": "<server wg pubkey>", "preshared_key": "<per-device psk>", "keepalive_seconds": 25},
    {"name": "fra-01-ss", "protocol": "shadowsocks", "endpoint": "203.0.113.10:8443",
     "method": "chacha20-ietf-poly1305", "password": "<per-user derived secret>"}
  ],
  "tunnel_addresses": ["10.64.0.7/32"],
  "dns_servers": ["10.64.0.1"],
  "mtu": 1420
}
```
- **Server selection:** only `healthy` servers, filtered to the requested `country` if given
  (falling back to all countries if none are healthy there). Ranked by
  `score = rtt_ms_p50 + 400*load + 200*loss`, ascending. The top 3 servers are each emitted
  as a WireGuard entry followed by a Shadowsocks fallback entry, so the engine races them.
- **Shadowsocks password** (per user, per server, never stored):
  `base64std(HMAC_SHA256(server_ss_master_secret, "ss-user:" + user_id))`, which is 44 chars.
  The server-side multi-user Shadowsocks node runs the same derivation.
- **Preshared key** is generated per (device, server) on first issuance and stored encrypted.
- **Secrets at rest:** `ss_master_secret` and preshared keys are encrypted with AES-256-GCM
  under `DATA_ENCRYPTION_KEY` (32 bytes, base64, from env/secret manager), stored as
  `v1:<base64(nonce|ciphertext)>`. The key id prefix allows rotation.
- **IPAM:** each device gets a unique /32 from `10.64.0.0/10`, excluding .0 and .1 of the
  pool. Allocation is race-safe via a unique constraint plus retry. The DNS address is `10.64.0.1`.
  Addresses are handed out sequentially; once the end of the pool is reached, addresses freed by
  deleted devices are reused. When no address is free, registration answers `503` + `Retry-After`.

## Admin API (api, `/admin/v1`), `Authorization: Bearer $ADMIN_TOKEN`
| POST | `/admin/v1/servers` | `{name, country, city, public_ipv4, wg_port, wg_public_key, ss_port, ss_master_secret?}` → 201. Generates `ss_master_secret` if absent |
|---|---|---|
| GET | `/admin/v1/servers/{id}/peers` | what a node agent pulls to configure WireGuard: `[{device_id, wg_public_key, tunnel_address, preshared_key}]`. Optional `?limit=N&cursor=C` (keyset pages, default 1000, max 10000, next page in `X-Next-Cursor` / `Link`) and `?since=T` (incremental sync, see below) |

### Node agent peer sync
A busy node has 100k+ peers, so agents should not re-download the full list every interval:

1. **Full sync** (start-up, or after a `410`): page with `?limit=1000`, following `X-Next-Cursor`
   until it is absent. Keep the `X-Sync-Token` response header (identical on every page of one walk).
2. **Incremental sync** every 15-30 s: `GET .../peers?since=<token>` →
   `{"upserts": [Peer...], "removals": ["<device_id>"...], "sync_token": "..."}`. Apply upserts,
   then removals; store the new token. Changes covered: new peers on this node, subscription
   renewals/refunds/revocations, **expiry by time with no event**, deleted devices and accounts.
   Results may repeat changes from just before the token (a 60 s overlap closes commit races);
   both operations are idempotent.
3. A token older than ~24 h (removal retention) gets `410`: do a full sync.

Without query parameters the endpoint returns the whole array exactly as before.
Tokens and cursors are opaque strings and are only valid against the same deployment.

## Internal API (api, `/internal/v1`), HMAC service auth

### `GET /internal/v1/servers` (fleet-prober)
`[{"id": "...", "name": "fra-01", "public_ipv4": "203.0.113.10", "wg_port": 51820, "ss_port": 8443}]`

### `POST /internal/v1/servers/heartbeats` (fleet-prober)
```json
{"prober_id": "prober-eu-1",
 "observed_at": "2026-10-02T12:00:00Z",
 "results": [
   {"server_id": "...", "reachable": true, "rtt_ms_p50": 41.5, "rtt_ms_p95": 63.0,
    "loss": 0.0, "load": 0.35}
 ]}
```
→ 202 `{"accepted": 1}`. The api marks a server **unhealthy** after 3 consecutive unreachable
results, or when no heartbeat has arrived for 90 s. It marks it healthy again after 2
consecutive reachable results. `load` is 0..1 (`null` if unknown, in which case the last
value is kept).

### `POST /internal/v1/entitlements` (billing-webhooks)
```json
{"event_id": "evt_123", "source": "stripe" | "app_store" | "google_play",
 "user_id": "<uuid>", "product_id": "premium_monthly",
 "status": "active" | "grace" | "expired" | "revoked" | "refunded",
 "expires_at": "2026-11-02T12:00:00Z", "original_transaction_id": "...",
 "occurred_at": "2026-10-02T12:00:00Z"}
```
→ 200 `{"applied": true}` or `{"applied": false, "reason": "duplicate"|"stale"}`.
- **Idempotent** on `event_id`.
- **Ordering:** an event whose `occurred_at` is older than the latest one already applied
  for the same `(source, original_transaction_id)` is `stale` and ignored. Store webhooks
  arrive out of order.
- **Active** means status `active` or `grace` with `expires_at` in the future. Plan becomes
  `premium` while active and `free` otherwise.

## Billing service (billing-webhooks, Node)
| POST | `/billing/stripe/webhook` | Verify `Stripe-Signature` (`t=…,v1=…`, HMAC-SHA256 of `t.payload`, 5 min tolerance, raw body). Handle `checkout.session.completed`, `customer.subscription.updated/deleted`, `invoice.payment_failed`. `user_id` from `client_reference_id` / subscription `metadata.user_id` |
|---|---|---|
| POST | `/billing/apple/notifications` | App Store Server Notifications v2: `{signedPayload}` JWS. Verify the x5c chain up to the Apple Root CA G3 (path from `APPLE_ROOT_CA_PATH`), then the ES256 signature. Map `SUBSCRIBED`, `DID_RENEW`, `EXPIRED`, `DID_FAIL_TO_RENEW` (grace), `REFUND`, `REVOKE`. `user_id` comes from `appAccountToken` |
| POST | `/billing/google/rtdn` | Pub/Sub push of Real-Time Developer Notifications. Verify `Authorization: Bearer` equals `GOOGLE_PUSH_TOKEN` (constant time). Decode `message.data` (base64 JSON) and map `subscriptionNotification.notificationType`. Then look the purchase up via a `GooglePlayClient` interface (real impl calls the Android Publisher API; a fake is used in tests) to get expiry and `obfuscatedExternalAccountId` = user_id |
| POST | `/billing/apple/verify` | app, user JWT: `{signed_transaction}`. Verify as above, and require `appAccountToken == sub` |
| POST | `/billing/google/verify` | app, user JWT: `{purchase_token, product_id}`. Verify via GooglePlayClient, and require `obfuscatedExternalAccountId == sub` |
| GET | `/healthz` | |

Every accepted event is forwarded to `POST /internal/v1/entitlements`, retrying with
exponential backoff and jitter (max 5 attempts) on 5xx or network errors. The webhook is
answered 2xx only after the api accepts the event, so stores and Stripe redeliver on failure.
Duplicate deliveries are short-circuited with a Redis `SET NX` on `event_id` (TTL 7 days)
**after** a successful forward.

## Fleet prober (fleet-prober, Python)
- Every `PROBE_INTERVAL_S` (default 15), it fetches `/internal/v1/servers` and probes each server
  concurrently (asyncio, bounded concurrency):
  - **TCP connect RTT** to `ss_port`: 5 samples.
  - **UDP RTT and loss** against the node's UDP echo health port (`wg_port + 1`): 5 samples.
    WireGuard deliberately never answers unauthenticated packets, so probing `wg_port` itself
    can't distinguish "up" from "blackholed". A tiny echo port beside it is the standard
    workaround, and it is part of the node-agent contract.
  - `reachable` is true if either probe got at least one reply. `rtt_ms_*` and `loss` come
    from the UDP samples when available, otherwise from the TCP ones.
  - `load` comes from an optional node metrics endpoint `http://<ip>:9100/load`
    (`{"load": 0.35}`). Timeout or 404 means `null`.
- Results are posted as one heartbeat batch. A Prometheus metrics endpoint on `:9101` exposes
  probe counts and latencies.
- Config via env: `API_URL`, `PROBER_ID`, `PROBER_SERVICE_SECRET`, `PROBE_INTERVAL_S`,
  `PROBE_CONCURRENCY`, `PROBE_TIMEOUT_S`.
