# Design

The inter-service contract is in [CONTRACT.md](CONTRACT.md), and scale and capacity are in [SCALABILITY.md](SCALABILITY.md).

## Security design

- **The private key never reaches the server.** The phone generates its WireGuard key, and the api stores only the public key.
- **Passwords** use argon2id (OWASP parameters) with a concurrency cap, constant-time verification, a dummy verify that equalises timing for unknown emails, and a hash upgrade on login.
- **Tokens**: 15-minute EdDSA access JWTs. The `kid` is an RFC 7638 thumbprint, keys are published as JWKS, and rotation is supported. Opaque refresh tokens are stored as SHA-256 and rotate on every use; **reuse of a rotated token revokes the whole family**.
- **Secrets at rest**: Shadowsocks master secrets and per-device preshared keys use AES-256-GCM (`v1:` versioned, so keys can rotate). AAD binds each ciphertext to its row.
- **Per-user Shadowsocks passwords** are `HMAC(server_secret, user_id)`, derived on demand and never stored.
- **Service-to-service auth**: HMAC-SHA256 over timestamp, method, path and body, with a 300 s window and constant-time comparison. Each caller has its own secret and an allow-list of routes.
- **Store webhooks**: Stripe signatures are verified manually (visible logic, timing-safe). Apple JWS checks the x5c chain to Apple Root CA G3 plus Apple's OIDs before ES256. Google uses a bearer token, then a Play Developer API lookup. Purchases are bound to the user (`appAccountToken` / `obfuscatedExternalAccountId` must equal the JWT `sub`).
- **Entitlements** are idempotent on `event_id` and order-safe: older events per transaction are ignored as stale, because stores deliver out of order. Being active is computed at read time, so access lapses at expiry even if no "expired" webhook ever arrives.
- **Rate limiting**: a Redis sliding window driven by the Redis server clock. Auth endpoints **fail closed** if Redis is down; everything else fails open and the fail-open count is a metric.
- **Privacy**: logs are structured JSON with no emails, IPs, tokens, keys or receipts.

## Reliability design

- Fleet health is a hysteresis state machine: a server goes unhealthy after 3 bad results, or after 90 s with no heartbeat (checked at read time, so it still works if every prober dies), and healthy again only after 2 good results.
- Selection score is `rtt_p50 + 400·load + 200·loss`, with a country preference that falls back to all countries. The app gets the top 3 servers, so the engine can race them.
- IPAM is race-safe (unique constraint plus savepoint retry), and the device limit is enforced under a row lock.
- Migrations are embedded and transactional under an advisory lock, so several replicas can start at once.
- Webhooks are acknowledged to the store only after the api accepted the event, so failures are redelivered. The billing service retries with exponential backoff and jitter.
- The api shuts down gracefully, and has `/healthz` and `/readyz` (DB + Redis) and Prometheus metrics in every service.

## Node agent

- **The api is the gatekeeper; nodes enforce.** There is nothing in the data path between a phone
  and a node: the WireGuard handshake goes straight to the node. Access is controlled by which peers
  each node accepts, and the agent keeps that list equal to "devices issued this node whose owner is
  entitled right now".
- **Incremental sync** every 15 s (`?since=`), so a lapsed user loses access within one interval,
  and a 100k-peer node pays milliseconds per sync, not a full download.
- **Fails static.** If the api is unreachable the agent changes nothing. An api incident must not
  become a VPN outage for every connected user.
- **Owns the interface.** A periodic full sync removes peers the api doesn't list (added by hand,
  left over from a crash) and repairs changed preshared keys.
- **Least privilege.** Each agent holds a token derived for its own server id; it can read that
  node's peers and nothing else. Rotating `NODE_AGENT_SECRET` revokes all of them.
- **Secrets hygiene.** Preshared keys reach `wg(8)` as 0600 files in a 0700 directory (a tmpfs in
  the container), never on the command line where `/proc` would expose them. Logs carry only a
  short public-key prefix.
- **Health endpoints.** The UDP echo port answers only datagrams ≤ 64 bytes at the same size, so it
  can't be used for amplification.
