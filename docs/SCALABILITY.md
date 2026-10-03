# Slipstream Control: scalability

Target: 10M+ installs, millions of accounts, 1,000+ VPN nodes in 45+ countries.
This document covers the architecture for that scale, the capacity math, the
measured load-test and query-plan results behind it, and what breaks first.

Everything measured here was run on **one 2-vCPU / 7 GB VM shared by the api,
Postgres 16, Redis 7 and the load generator**, against a seeded dataset of
1M users (details in [Reproducing](#reproducing)). The box was also shared with
other workloads, so every run first waited until other processes used <15% CPU.
Throughput figures are therefore conservative. **CPU per request** is the figure
that transfers to production, because it does not depend on what else shared the box.

## 1. Architecture

```
             clients (10M installs)           node agents (1,000+)     probers (N)
                       │ HTTPS                         │                    │
                ┌──────▼─────────────── L7 load balancer (TLS) ─────────────▼──┐
                │  X-Forwarded-For appended; LB subnets = TRUSTED_PROXY_CIDRS   │
                └──────┬─────────────┬─────────────┬───────────────────────────┘
                 ┌─────▼────┐  ┌─────▼────┐  ┌─────▼────┐   stateless api replicas
                 │ api      │  │ api      │  │ api  ... │   (HPA on CPU, >=3 across AZs)
                 └─┬──────┬─┘  └─┬──────┬─┘  └─┬──────┬─┘
                   │      └──────┼──────┴──────┼───────────► Redis (rate limits only;
                   │             │             │             primary + replica/Sentinel,
                   ▼             ▼             ▼             or Cluster: single-key scripts)
             PgBouncer (transaction mode, per AZ)
                   │
             Postgres primary ──streaming──► replicas (HA failover; read offload later)
```

**Every api replica is interchangeable.** That is what lets the service scale out
by adding replicas. Each item below was verified in code and covered by tests:

| Concern | How it holds with N replicas |
|---|---|
| Rate limits | Redis sliding window driven by the Redis server clock, keyed per IP hash, email hash or user. Shared by all replicas. |
| Auth | Stateless EdDSA JWTs. Every replica has the same key from the secret manager. Refresh rotation is a row lock in Postgres. |
| Migrations | Run in one transaction under `pg_advisory_xact_lock`, so replicas starting together serialise. A transaction-scoped lock works through PgBouncer. |
| Janitor (token / tombstone cleanup) | Was: a session advisory lock (breaks under PgBouncer transaction pooling), every replica every hour, unbatched `DELETE` with a seq scan. **Now:** a lease row in `maintenance_leases` (one upsert, so it works through any pooler) held for the interval. Cleanup runs **once per hour across the whole fleet**, in index-backed batches of 5,000. A crashed holder's lease expires. |
| Caches | Only soft state. The server-list snapshot is ≤ `SERVER_CACHE_TTL` (2 s) old on each replica. Writes through a replica invalidate its own snapshot at once. Losing a replica loses nothing. |
| Health | The 90 s silence rule is applied at read time, on each request's clock, so it holds with stale snapshots, dead probers, or any replica answering. |
| IPAM | `UNIQUE(tunnel_ip)` and savepoint retry. No in-process allocator state. |
| Shutdown | SIGTERM makes `/readyz` report `draining` (503). After `SHUTDOWN_DRAIN_DELAY` the listener closes and in-flight requests finish. |

**PgBouncer** in transaction mode is required at scale, because N replicas ×
`DB_MAX_OPEN_CONNS` quickly exceeds what Postgres should hold (≈ 100–300 backends).
The api is compatible with it:
- lib/pq uses unnamed prepared statements;
- nothing relies on session state (no session advisory locks, `SET`, or temp tables);
- every multi-statement unit is a transaction.

**Read replicas**: today every query goes to the primary. Two things can move to
replicas without read-your-writes problems, behind a future `DATABASE_READ_URL`:
- the server snapshot load (0.5 queries/s per replica);
- the node agents' peer sync.

Account reads stay on the primary (a device registered and then configured
immediately must be visible).

## 2. Capacity math for 10M installs

Assumptions (round, deliberately pessimistic):

| | |
|---|---|
| Installs / accounts | 10M |
| Daily active (DAU) | 30% = 3M |
| Paying subscribers | 15% = 1.5M; 60% of them connect daily = 0.9M premium DAU |
| Devices | 1.6 per subscriber = 2.4M |
| Per DAU per day | 3 app opens (`GET /v1/servers`), 2 `/v1/me`, 3 refreshes (15-min access tokens), 0.02 logins |
| Per premium DAU per day | 4 connects, each a `POST /v1/devices/{id}/config` |
| Node agents | 1,000 nodes, incremental peer sync every 30 s |
| Probers | 3, one batch of 1,000 results every 15 s each |

| Traffic | Per day | Average | Peak (×3) |
|---|---|---|---|
| `/v1/servers` | 9M | 104/s | 310/s |
| `/v1/me` | 6M | 69/s | 210/s |
| refresh | 9M | 104/s | 310/s |
| config issuance | 3.6M | 42/s | 125/s |
| login + signup | 90k | 1/s | 3/s (attacks: see §5) |
| peer sync (agents) | 2.9M | 33/s | 33/s |
| **Total** | ~30M | **~350/s** | **~1,000/s** |

**Reconnect storm.** This is the sizing case: an outage ends, or a large node
group fails and its clients reconnect. 0.9M premium clients re-fetching config
over about 2 minutes is ~7,500 config/s, plus as many `/v1/servers` and a
share of refreshes, so about **15–20k req/s for a few minutes**.

**Per-request cost (measured, hot-path mix, quiet box).**
- api: **0.40 ms CPU**/request, so 1 core ≈ 2,500 req/s.
- Postgres: **0.5 ms CPU**/request, so 1 core ≈ 2,000 req/s.
- Redis: **0.05 ms**/request.
- A login costs **~31 ms of api CPU** (argon2id, OWASP 19 MiB / t=2), so 1 core ≈ 32 logins/s.

**Sizing.**
- **Normal peak (~1,000 req/s):** 3 api replicas × 2 vCPU (one per AZ; ~0.4 cores
  busy in total, i.e. N+2 headroom). Postgres primary with 4 vCPU (~0.5 core busy).
  One small Redis.
- **Storm (20k req/s):** api needs ~8 cores at 100%, i.e. ~6 replicas × 2 vCPU at
  70%. HPA scales out, and until it does, replicas shed with 503 + `Retry-After`.
  Postgres needs ~10 cores of the hot-path mix. A 16-vCPU primary absorbs it.
  Alternatively, clients reuse their last config, which is valid until the
  device's keys change, and only re-fetch when every server in it fails. That
  cuts the storm by an order of magnitude and is the recommended client change.
- **Redis:** 20k req/s × 0.05 ms = 1 core. Rate-limit keys hold at most `limit`
  entries per key (≈ 90k entries ≈ 10 MB at 1,000 req/s), well within a single node.

## 3. Load test results

`cmd/loadtest` (stdlib only, plus the repo's stdlib `svcauth`) setup phase:
3,000 users created through the real API (argon2 signup), each entitled through
the signed internal endpoint, logged in, and given one device. A background
goroutine acts as the prober and posts signed heartbeats for all 1,000 servers
every 15 s. Closed-loop workers own disjoint users, so refresh rotation is never
racing itself. Rate limits stay **on**: the api trusts `127.0.0.1/32`
(`TRUSTED_PROXY_CIDRS`) and every request carries a random `X-Forwarded-For`
from 100.64.0.0/10. No production code path is disabled for load testing.

Mix "standard": `servers=30, me=25, config=25, refresh=15, login=5`. 60 s per run.
Latencies in ms (p50 / p99). "before" is the code as received (0001 schema).
"after" is this change (0002 schema and code).

| run | workers | req/s | config | me | servers | refresh | login (ok/s) | heartbeat batch (1,000 results) | api CPU ms/req | PG CPU ms/req |
|---|---|---|---|---|---|---|---|---|---|---|
| before | 8 | 151 | 88 / 603 | 17 / 95 | 26 / 80 | 27 / 123 | 131 / 330 (8/s) | 887 / 1,837 | 8.43 | 2.83 |
| before | 32 | 165 | 359 / 1,656 | 90 / 364 | 72 / 239 | 107 / 379 | 297 / 789 (8/s) | 1,644 / 3,180 | 7.46 | 2.94 |
| before | 96 | 137 | 1,528 / 4,129 | 459 / 1,697 | 176 / 867 | 240 / 1,020 | 530 / 1,526 (7/s) | 3,594 / 5,896 | 6.68 | 2.83 |
| **after** | 8 | **547** | 12 / 68 | 7 / 50 | 6 / 31 | 10 / 62 | 58 / 161 (27/s) | 66 / 119 | 2.05 | 0.53 |
| **after** | 32 | **571** | 69 / 196 | 41 / 142 | 22 / 69 | 55 / 164 | 160 / 379 (28/s) | 83 / 215 | 1.98 | 0.55 |
| **after** | 96 | **628** | 259 / 588 | 156 / 412 | 30 / 109 | 101 / 291 | 323 / 626 (29/s)¹ | 174 / 331 | 1.81 | 0.53 |

Hot path without logins (`servers=30, me=25, config=30, refresh=15`):

| run | workers | req/s | config | me | servers | refresh | heartbeat batch | api CPU ms/req | PG CPU ms/req |
|---|---|---|---|---|---|---|---|---|---|
| before | 32 | 225 | 257 / 1,105 | 72 / 237 | 58 / 166 | 84 / 269 | 2,086 / 16,047 | 4.66 | 2.68 |
| **after** | 32 | **1,205** | 28 / 78 | 22 / 66 | 21 / 77 | 26 / 74 | 68 / 112 | **0.40** | **0.49** |
| **after** | 96 | **1,341** | 78 / 227 | 65 / 199 | 51 / 204 | 64 / 199 | 122 / 159 | 0.37 | –² |

Login overload (`login=100`, 64 workers, clients honour `Retry-After`):

| run | logins ok/s | login p50 / p99 | shed (503 + Retry-After) | api CPU per login |
|---|---|---|---|---|
| before | 54 | 1,147 / 1,797 (unbounded queue) | 0 | 32 ms |
| **after** | 56 | **193 / 312** | 3,111 in 60 s, answered in < 1 ms | 31 ms |

¹ The 503s in the 96-worker run are argon2 load shedding (8% of logins), by design.
No other errors occurred in any run.
² The per-process CPU sample for Postgres was unreliable in that one run. A repeat
measured 0.40 ms/req.

Run-to-run variance on this shared box is about ±10% (repeats: after/32/standard
518 req/s, after/32/hot-path 1,152 req/s, before/32/hot-path 190 req/s).

**On this box, the hot path got 5.3× more throughput** (225 → 1,205 req/s).
api CPU per request fell 11.6× (4.66 → 0.40 ms), and Postgres CPU per request
fell 5.5× (2.68 → 0.49 ms). At the "after" hot-path numbers the
machine is saturated by the three tenants together (api 0.48 cores,
Postgres 0.50, **the load generator 0.55**), so a dedicated 2-vCPU api replica
would sustain about 4,000–5,000 req/s of this mix.

### What the profiles showed, and the fixes

1. **Heartbeat ingestion held every server row locked for seconds.** It did 2,000
   sequential statements (`SELECT … FOR UPDATE` and `UPDATE` per server) in one
   transaction: 0.9–6.7 s per batch. **Fix:** two statements per batch,
   `SELECT … WHERE id = ANY($1) ORDER BY id FOR NO KEY UPDATE` and
   `UPDATE … FROM unnest(...)`. Batches now take 60–170 ms end to end under load.
2. **Deadlock and blocking between heartbeats and config issuance (found by the
   load test).** The heartbeat lock was `FOR UPDATE`, which conflicts with the
   `KEY SHARE` locks that the foreign-key check on `device_server_keys.server_id`
   takes. Every first-time config issuance therefore waited behind the batch.
   Once preshared-key inserts were batched, the two deadlocked (500 after
   `deadlock_timeout`). **Fix:** `FOR NO KEY UPDATE` (health columns are not keys)
   and inserting keys in id order. The device-limit lock on `users` likewise
   became `FOR NO KEY UPDATE`, so it no longer blocks logins and billing inserts
   for that user. Regression test: `TestHeartbeatsDoNotBlockOrDeadlockConfigIssuance`.
   It fails 2 runs in 3 on the old locking.
3. **The whole server table was read and re-encoded per request.** `/v1/servers`
   and config issuance each read and scanned 1,000 rows. `/v1/servers` also JSON-encoded ~150 KB, and
   config issuance sorted the fleet. **Fix:** a per-replica snapshot
   (`internal/httpapi/servercache.go`):
   - TTL 2 s, single-flight refresh (one load serves all waiters, and the load is
     detached from the first caller's cancellation);
   - generation-based invalidation, so a write during an in-flight load is never
     hidden;
   - pre-encoded JSON, pre-gzipped body (~25 KB) and an `ETag` (`If-None-Match` → 304);
   - the fleet pre-ranked by score once per snapshot (`selection.Ranking`, proven
     equal to `selection.Rank` by a randomized test). Health is still applied per
     request.
4. **Six round trips for preshared keys on every config fetch.** Each fetch did
   `INSERT … ON CONFLICT` plus `SELECT` per server, and generated and encrypted a
   new PSK each time only to discard it. **Fix:** one `SELECT … server_id = ANY($2)`
   in the steady state. Only missing keys are generated, then inserted in one
   statement.
5. **argon2 queued without bound.** Concurrency was 2×GOMAXPROCS with waiters
   queued until their context ended. Under a login burst every login slowed to
   seconds and the CPU starved everything else. **Fix:** concurrency = GOMAXPROCS,
   at most 4×GOMAXPROCS waiters, each for at most 1 s; beyond that `ErrBusy` →
   503 + `Retry-After: 1`. Unknown emails are admitted exactly like known ones,
   so saturation does not leak whether an account exists. The limits are
   configurable (`ARGON2_*`).

What remains on the profile with logins in the mix is argon2 (~73% of api CPU),
which is inherent to the parameters. On the no-login hot path:

| Share of api CPU | Where |
|---|---|
| ~24% | Ed25519 verification of the access token on every request (~50 µs) |
| ~18% | socket write syscalls, one per round trip (config issuance makes 3 DB and 1 Redis) |
| rest | spread across JSON, lib/pq and GC |

Next steps, if the api ever becomes the bottleneck rather than Postgres:
- cache verified tokens by SHA-256 of the token until their `exp` (saves most of
  the 24%);
- fold the device and entitlement reads of config issuance into one query.

### Peers endpoint on a busy node (101k entitled peers of 117k keys)

| | before | after |
|---|---|---|
| full list, no parameters (unchanged contract) | 1.0–1.2 s, 21.7 MB, SQL: parallel seq scan of `devices` + hash join + external sort | 0.9–1.1 s, same body |
| paged, `?limit=1000` | n/a | **18 ms/page average** (worst 47 ms), 102 pages = 1.9 s, and the cost is flat at any depth |
| incremental, `?since=<token>` | n/a | **3–6 ms** when nothing changed. Cost scales with the number of changes, not with node size |

An agent syncing every 30 s moves from 21.7 MB and ~1 s of DB time per sync to a
few KB and a few ms.

## 4. Data layer: EXPLAIN (ANALYZE, BUFFERS) before and after

Seeded dataset (`cmd/loadtest/seed`, all via `generate_series` except encrypted
columns):
- 1M users;
- 1.47M devices (1.5M minus 2% churn, leaving gaps in the address space);
- 770k subscriptions;
- 4.9M entitlement events;
- 3M refresh tokens (10% long-expired);
- 1,000 servers;
- 1.88M per-(device, server) preshared keys, including a hot node with 117k keys.

Every query the api issues was explained. Only those that changed or matter are
listed; the plain-text plans are in the load-test scratch output.

| Query (path) | Before | After |
|---|---|---|
| Login: `users WHERE email = $1` | Index Scan `users_email_key`, 0.5 ms | unchanged. Emails are lower-cased at write and a `CHECK (email = lower(email))` enforces it, so no `lower()` expression index is needed |
| Refresh: `refresh_tokens WHERE token_hash = $1 FOR UPDATE` | Index Scan `refresh_tokens_token_hash_key`, 0.12 ms | unchanged |
| Devices by user, count by user | Index (Only) Scan `devices_user_idx`, < 0.1 ms | unchanged |
| `wg_public_key` uniqueness | Index Only Scan `devices_wg_public_key_key`, 0.26 ms | unchanged |
| Entitlement: `subscriptions WHERE user_id` | Index Scan `subscriptions_user_idx`, 0.16 ms | unchanged |
| Latest state per (source, original_transaction_id) | `subscriptions` PK upsert with `WHERE last_event_at <= EXCLUDED.last_event_at`, 0.24 ms | unchanged. `entitlement_events` is never read on a hot path; it is the idempotency key and the audit log |
| **Janitor: delete expired refresh tokens** | **Seq Scan** 3M rows, one 300k-row `DELETE`, **3,125 ms**, on every replica every hour | `refresh_tokens_expires_idx`, batches of 5,000 (~150 ms each, 11 ms to find), once per hour fleet-wide |
| **Delete account (FK cascade into `entitlement_events`)** | **Parallel Seq Scan** 4.9M rows, **800 ms** with the user row locked | `entitlement_events_user_idx`, 0.07 ms; whole cascade 6.9 ms |
| **Peers of the hot node** | Parallel Seq Scan of 1.5M devices + hash join + external sort (9 MB on disk), **2,128 ms** per sync | paged: ordered `LIMIT` range scan on `device_server_keys_server_peer_idx`, then join: **19–23 ms per 1,000 at any depth** |
| Peers, keyset as a single join (rejected design) | – | with default `random_page_cost=4`, the planner picks bitmap scan + top-N sort over all remaining keys: 160–720 ms per page (O(n)). Fast only with `random_page_cost=1.1`, so it is not used |
| Peer delta (`since`) | – | `device_server_keys_server_peer_idx`, `subscriptions_updated_idx`, `subscriptions_expiring_idx`, `peer_tombstones_server_idx`: ~1 ms |
| Heartbeat batch (1,000 servers) | 2,000 statements, each a PK lookup (0.08 + 0.24 ms) | 1 `FOR NO KEY UPDATE` (Bitmap on `servers_pkey`, 3.2 ms) + 1 `UPDATE … FROM unnest` (7.2 ms) |
| Config: preshared keys | 3 × (`INSERT ON CONFLICT` + `SELECT`) | 1 × `SELECT … ANY()` on `device_server_keys_pkey`, 0.03 ms |
| IPAM: max+1 | Index Only Scan Backward `devices_tunnel_ip_key`, 0.4 ms | same, bounded to the range: 0.07 ms |
| IPAM: reuse freed addresses | random probing: failed spuriously on a nearly full pool, returned **500** when exhausted | index-only gap search from a random point (walked 27 entries, 0.7 ms) with wrap-around. Exact: exhaustion only when nothing is free, then a clean **503 + Retry-After** |
| Device delete (keys cascade + tombstone trigger) | 0.14 ms | 0.19 ms (statement-level trigger with a transition table: one `INSERT` per `DELETE`) |

**IPAM correctness.**
- max+1 stays index-backed (Index Only Scan Backward).
- After deletions, gaps are reused only once the cursor reaches the end of the
  range, so a freed address is not reissued at once.
- Concurrent allocators re-read the max after a unique violation and retry with
  a small random skip, falling back to the gap search.

Tests cover exhaustion (503), reuse of a middle and of the first address, and a
48-way concurrent herd (all unique). The pool is still global: see §5.

### Indexes added (`migrations/0002_scale_indexes.sql`), sizes on the seeded data

| Index | Size | Serves |
|---|---|---|
| `refresh_tokens_expires_idx (expires_at)` | 20 MB | janitor |
| `refresh_tokens_revoked_idx (revoked_at) WHERE revoked_at IS NOT NULL` | 16 kB | janitor (revoked families) |
| `entitlement_events_user_idx (user_id, occurred_at)` | 190 MB | FK cascade on account deletion, billing history |
| `device_server_keys_server_peer_idx (server_id, created_at, device_id)` | 108 MB | peer pages, delta "new keys", FK cascade from servers. **Replaces** `device_server_keys_server_idx` (16 MB) |
| `subscriptions_updated_idx (updated_at)` | 5 MB | peer delta: changed subscriptions |
| `subscriptions_expiring_idx (expires_at) WHERE status IN ('active','grace')` | 4 MB | peer delta: lapses by time |
| `peer_tombstones (server_id, deleted_at)`, `(deleted_at)` | tiny | peer delta: removals, janitor |

New tables:
- `peer_tombstones`, filled by an `AFTER DELETE` statement trigger on
  `device_server_keys` (so every removal path records it, including account and
  server deletion cascades) and pruned after 24 h;
- `maintenance_leases`.

Applying 0002 to the seeded database took **11 s inside one transaction**, which
blocks writes to those tables while it runs. Production procedure: first run each
`CREATE INDEX CONCURRENTLY IF NOT EXISTS …` by hand. The migration then finds
the indexes and only creates the small objects.

### Database size

| Table | Rows (seeded) | Heap | Indexes | Total |
|---|---|---|---|---|
| entitlement_events | 4.90M | 700 MB | 444 MB | 1.14 GB |
| refresh_tokens | 2.77M | 408 MB | 518 MB | 0.93 GB |
| device_server_keys | 1.99M | 332 MB | 240 MB | 0.57 GB |
| devices | 1.47M | 209 MB | 260 MB | 0.47 GB |
| users | 1.00M | 174 MB | 106 MB | 0.28 GB |
| subscriptions | 0.77M | 99 MB | 92 MB | 0.19 GB |
| **database** | | | | **3.6 GB** |

Projected for 10M installs at the measured bytes per row:

| Table | Projection |
|---|---|
| users (10M) | 2.8 GB |
| devices (2.4M) | 0.8 GB |
| subscriptions | 0.4 GB |
| entitlement_events | **+5 GB per year** (≈ 22M events/yr) |
| device_server_keys | 14 GB if keys never expire (≈ 20 servers per device over time); 3.5 GB with a 30-day key expiry |
| refresh_tokens | **≈ 94 GB** (3M DAU × 3 rotations/day × 31 days retention ≈ 280M rows, plus a ~20 GB hash index) |

## 5. What breaks first, and the plan

In order of when it bites:

1. **Login CPU (argon2).** ~32 logins/s per core. A credential-stuffing run, or
   a mass re-login after a forced logout, can't be served by CPU alone.
   - *Now:* per-IP and per-email limits in Redis (failing closed); bounded argon2
     admission that sheds with 503 in < 1 ms; non-login traffic keeps its latency.
   - *Next:* route `/v1/auth/*` to a separate replica pool so a login storm cannot
     take CPU from config issuance; add per-ASN limits and a proof-of-work or
     CAPTCHA step for abusive sources.
2. **Reconnect storms on config issuance** (15–20k req/s for minutes).
   - *Now:* snapshot cache; one-query PSK path; transient DB errors are 503 +
     `Retry-After` (not 500).
   - *Next:* HPA on CPU with a floor of 3; client-side jittered backoff; and
     clients reusing their last config, which removes most of the storm.
3. **Postgres connections.** N replicas × `DB_MAX_OPEN_CONNS` (default 20).
   PgBouncer in transaction mode before going past ~5 replicas. The code is
   compatible with it (the lease row replaced the session advisory lock).
4. **`refresh_tokens` growth.** This is the largest table at scale. Every
   rotation adds a row, kept until expiry plus 1 day for reuse detection. Plan:
   - now: revoked families are pruned a day after revocation;
   - next: partition by `created_at` (daily or weekly) and drop old partitions
     instead of `DELETE`;
   - next: keep rotated rows for 7 days, not 30 (shrinks the theft-detection
     window for very old tokens: a product decision);
   - longer term: one row per family with the current hash, plus a small ring of
     recent hashes.
5. **IPAM pool: 4.19M global addresses.** 10.64.0.0/10 minus the reserved ones,
   unique across the fleet. 2.4M devices is 57% full, and exhaustion is now a
   clean 503. WireGuard addresses only need to be unique **per node**, so the
   durable fix is per-node (or per-region) address spaces or IPv6 ULA. Until
   then, reclaim addresses of devices whose owners lapsed > 90 days ago.
6. **Peer lists grow with history.** A node lists every entitled device that was
   ever issued a key for it. Plan:
   - add `last_issued_at` to `device_server_keys`;
   - expire keys not issued for 30 days (the tombstone trigger already turns that
     into delta removals for the agents).

   This also cuts the table to ~3.5 GB.
7. **`entitlement_events` growth (+5 GB/yr).** Partitioning plan:
   - `PARTITION BY RANGE (received_at)`, monthly, created ahead by a job or pg_partman.
   - A partitioned table's PK must include the partition key, so idempotency
     moves to a narrow `entitlement_event_ids (event_id PRIMARY KEY, received_at)`
     table (~60 B/row, ~1.3 GB/yr), inserted `ON CONFLICT DO NOTHING` first in
     the same transaction. Stores redeliver within days, so that table can itself
     be pruned after 90 days.
   - Local indexes `(user_id, occurred_at)` per partition keep the account-deletion
     cascade index-backed.
   - Partitions older than the audit retention (e.g. 25 months) are detached and
     archived to object storage.
   - Hot paths never read this table, so nothing user-facing changes.
   - Migration: create the partitioned table, dual-write, backfill in batches, swap
     names in one transaction.
8. **Heartbeat ingestion.** One transaction locks the fleet's rows (`NO KEY UPDATE`,
   so config issuance is never blocked by it). Batches from several probers
   serialise at ~0.1 s each, which is fine up to ~10k servers and several probers.
   Beyond that, write per-prober results to a narrow table and fold them
   asynchronously.
9. **Redis.** 0.05 ms per request, so a single node handles > 15k req/s. Keys are
   independent single-key scripts, so Redis Cluster works without change.

## 6. Configuration (all optional; defaults in parentheses)

| Variable | Meaning |
|---|---|
| `DB_MAX_OPEN_CONNS` (20), `DB_MAX_IDLE_CONNS` (= open), `DB_CONN_MAX_LIFETIME` (30m), `DB_CONN_MAX_IDLE_TIME` (5m) | database/sql pool. A bounded lifetime rebalances connections after failover or a PgBouncer change |
| `REDIS_POOL_SIZE` (10×GOMAXPROCS), `REDIS_MIN_IDLE_CONNS` (0), `REDIS_DIAL_TIMEOUT` (500ms), `REDIS_TIMEOUT` (250ms read/write), `REDIS_POOL_TIMEOUT` (500ms) | go-redis pool. Context deadlines are honoured (`ContextTimeoutEnabled`) |
| `REQUEST_TIMEOUT` (10s) | deadline on every request's context, and with it every DB and Redis call. Below the HTTP server's `WriteTimeout` (30s) |
| `SERVER_CACHE_TTL` (2s; `0` disables; max 30s) | server-list snapshot lifetime |
| `ARGON2_MAX_CONCURRENCY` (GOMAXPROCS), `ARGON2_MAX_QUEUE` (4×concurrency), `ARGON2_QUEUE_TIMEOUT` (1s) | password-hashing admission |
| `SHUTDOWN_DRAIN_DELAY` (0) | time `/readyz` reports draining before the listener closes. Set to the LB's health-check interval × threshold plus a little |
| `DEBUG_ADDR` (off) | `net/http/pprof` on a separate listener. **Loopback only, enforced at startup** |

Statement timeouts can additionally be set server-side through the DSN, e.g.
`?options=-c%20statement_timeout%3D5000`.

## 7. Robustness checks (tests)

All run in `go test -race ./...` against real Postgres and Redis:

- **Postgres briefly unavailable** (`TestPostgresOutageReturns503`): a TCP proxy
  between the api and Postgres is cut, dropping live connections and accepting
  then closing new ones. Every endpoint returns **503 + Retry-After** (never 500,
  never a panic), `/readyz` reports `postgres: unavailable`, and the api recovers
  without a restart once the proxy is back.
- **Redis down** (`TestRedisDownPerContract`), with a real client pointed at a
  dead port: login fails closed (503), `/v1/me` fails open (200), `/readyz` is
  503, and all of it within the configured timeouts.
- **argon2 saturation** (`TestPasswordHashingSaturationSheds`, `TestHasherFailsFastWhenSaturated`).
- **Hostile bodies** (`TestHostileBodiesNever5xx`): every body-taking endpoint gets
  1e400, 30-digit integers, 20,000-deep arrays, 5,000-deep objects, invalid
  UTF-8, lone surrogates, NUL bytes, 60 KB strings, years 0000/9999/10000,
  trailing garbage and wrong types. None may produce a 5xx. **Found:** a NUL in
  `event_id`, `product_id` or `original_transaction_id` of an entitlement event
  reached Postgres (which rejects `\0` in text) and returned 500. Now rejected
  with 400.
- Snapshot cache: single-flight, TTL, clock going backwards, invalidation racing
  an in-flight load, waiter cancellation, and silence still detected through the
  cache.
- Peer sync end to end: paged walk = legacy list for page sizes 1–1000; then a
  delta after each of new peer, device deletion, account deletion (cascade),
  expiry event, renewal, and **lapse by time with no event**. After every step
  the agent state equals the server's list.

## Reproducing

```bash
createdb slipstream_load                      # never the test database: the seeder truncates
export DATABASE_URL='postgres://slipstream:slipstream@127.0.0.1:5432/slipstream_load?sslmode=disable'
export REDIS_URL=redis://127.0.0.1:6379/5 TRUSTED_PROXY_CIDRS=127.0.0.1/32 LOG_LEVEL=warn
# plus JWT_SIGNING_KEY, DATA_ENCRYPTION_KEY, ADMIN_TOKEN, BILLING_SERVICE_SECRET, PROBER_SERVICE_SECRET
go run ./cmd/loadtest/seed                    # ~7 min on 2 vCPU; refuses a DB whose name lacks "load"
go run ./cmd/api &                            # migrates, listens on LISTEN_ADDR
go run ./cmd/loadtest -url http://127.0.0.1:8080 -users 3000 -state lt.json -concurrency 32 -duration 60s
go run ./cmd/loadtest -url http://127.0.0.1:8080 -state lt.json -concurrency 96 \
   -mix servers=30,me=25,config=30,refresh=15 -json report.json
```

Flags: `-mix` (weighted `servers`, `me`, `config`, `refresh`, `login`, `devices`),
`-country-share`, `-heartbeats`, `-honor-retry-after`, `-procs` (process-name
prefixes for CPU accounting from `/proc`), `-json`.
