# fleet-prober

Measures every Slipstream VPN node from the outside and reports health to the control-plane
`api`. The api uses these heartbeats to decide which servers are `healthy` and how to rank them
when it issues a config (`score = rtt_ms_p50 + 400*load + 200*loss`). The contract this service
follows is in [`docs/CONTRACT.md`](../../docs/CONTRACT.md) ("Service-to-service", "Internal API",
"Fleet prober").

## What it does

Every `PROBE_INTERVAL_S` (± jitter, so several probers don't fall into step):

1. `GET /internal/v1/servers`, HMAC-signed.
2. Keeps the servers of its shard (`PROBER_SHARD=i/N`, see below) and probes them
   concurrently. An `asyncio.Semaphore` caps how many run at once (`PROBE_CONCURRENCY`), and
   every server gets a hard deadline. For each server it runs three probes in parallel:
   - **UDP echo** on `wg_port + 1`: 5 random 16-byte nonces, sent `PROBE_SAMPLE_GAP_S` apart
     (paced, not waiting for each echo), each with its own `PROBE_TIMEOUT_S`. Every nonce must
     come back unchanged; replies that don't match a nonce still waiting are ignored. From
     this it gets RTT p50/p95 and loss.
   - **TCP connect** to `ss_port`: 5 timed handshakes, paced the same way.
   - **Load**: `GET http://<ip>:9100/load` → `{"load": 0.35}`, via a minimal HTTP/1.1 client
     (one deadline, 8 KiB cap). A timeout, a non-200 response or a value outside 0..1 gives
     `null`, and the api then keeps the last known value.
3. Combines them per the contract. A server is `reachable` if either probe got a reply. RTT and
   loss come from UDP when it got replies, and from TCP otherwise. An unreachable server reports
   `rtt_ms_* = null` and `loss = 1.0`.
4. `POST /internal/v1/servers/heartbeats`, HMAC-signed, in chunks of at most
   `HEARTBEAT_BATCH_SIZE` (500) results, also split by size to stay far below the api's
   1 MiB body limit. All chunks share one `observed_at`; a failed chunk does not stop the
   others.

### Why not probe the WireGuard port directly?

WireGuard is silent by design. It drops any packet that isn't a valid, authenticated handshake
and sends nothing back: no reply, no ICMP. From outside, a healthy WireGuard port and a
blackholed one look the same. So the node agent runs a tiny UDP echo beside it on
`wg_port + 1`. That port uses the same host, the same network path and (in practice) the same
firewall and DDoS rules, so its RTT and loss are a good stand-in for the tunnel's. The TCP probe
against the Shadowsocks port is a fallback signal, and it also checks the fallback transport.

### Reliability

- **Retries**: api calls retry on network errors and 5xx, using exponential backoff with full
  jitter (`RETRY_ATTEMPTS`, `RETRY_BASE_S`, `RETRY_MAX_S`). A 4xx is not retried. Each attempt is
  signed again so the timestamp stays inside the api's 300 s window, and all attempts share one
  `X-Request-Id`.
- **Isolation**: probes turn network errors into lost samples, never exceptions. If one server's
  probe hits an unexpected bug, that server is left out of the batch and logged. It is not
  reported as down, because a bug in the prober is no evidence that the node is down. The api's
  90 s staleness rule covers it. A failed cycle is logged and the loop carries on.
- **No overlap**: cycles run back to back from one loop (a slow cycle delays the next one, it
  never runs beside it), and `run_cycle` refuses to start while another is running. A cycle
  longer than the interval is logged and counted (`fleet_prober_cycle_overruns_total`).
  Heartbeat retries stop at the next cycle's start, which will carry fresher data anyway.
- **Shutdown**: SIGTERM and SIGINT stop the loop. The cycle in flight gets up to 10 s to finish
  and post (give the container a stop grace period above that, e.g. 20 s).
- **Healthcheck**: `python -m fleet_prober --healthcheck` exits 0 if a cycle finished (even a
  failed one) within 3 intervals, read from the local metrics endpoint. The Dockerfile uses it.
- **Logs**: JSON on stderr. They never contain IPs or secrets, and identify servers by id.
  httpx's own request logging, which includes URLs, is turned down for that reason.

## Configuration (env vars)

| Var | Default | |
|---|---|---|
| `API_URL` | `http://localhost:8080` | api base URL |
| `PROBER_ID` | `prober-local` | e.g. `prober-eu-1` |
| `PROBER_SERVICE_SECRET` | required | HMAC secret shared with the api |
| `PROBE_INTERVAL_S` | `15` | cycle interval |
| `PROBE_CONCURRENCY` | `256` | servers probed at once; capped to fit the open-file limit |
| `PROBE_TIMEOUT_S` | `1.0` | per-sample timeout |
| `PROBE_SAMPLES` | `5` | samples per probe |
| `PROBE_SAMPLE_GAP_S` | `0.05` | spacing between samples |
| `PROBER_SHARD` | `0/1` | `i/N`: probe only the servers whose id hashes to `i` mod `N` |
| `HEARTBEAT_BATCH_SIZE` | `500` | max results per heartbeat POST (api limit: 5,000 and 1 MiB) |
| `INTERVAL_JITTER` | `0.1` | ± fraction applied to the interval |
| `LOAD_PORT` / `LOAD_TIMEOUT_S` | `9100` / `1.0` | node load endpoint |
| `METRICS_PORT` | `9101` | Prometheus endpoint (`0` disables it) |
| `RETRY_ATTEMPTS` / `RETRY_BASE_S` / `RETRY_MAX_S` | `5` / `0.5` / `8` | api retry policy |
| `SERVERS_FILE` | unset | read servers from JSON instead of the api (offline demo) |
| `LOG_LEVEL` | `INFO` | |

## Metrics (`:9101/metrics`)

| Metric | Labels |
|---|---|
| `fleet_prober_probe_samples_total` | `kind` = tcp, udp; `outcome` = ok, timeout, error |
| `fleet_prober_probe_rtt_seconds` (histogram) | `kind` |
| `fleet_prober_servers_probed_total` | `result` |
| `fleet_prober_cycles_total` | `outcome` |
| `fleet_prober_cycle_duration_seconds` | none |
| `fleet_prober_api_requests_total` | `endpoint`, `outcome` |
| `fleet_prober_fleet_listed` | none (servers in the api's listing) |
| `fleet_prober_fleet_servers` | none (servers this shard owns) |
| `fleet_prober_fleet_reachable` | none |
| `fleet_prober_last_success_timestamp_seconds` | none (all heartbeat chunks accepted) |
| `fleet_prober_last_cycle_timestamp_seconds` | none (any finished cycle; liveness) |
| `fleet_prober_cycle_overruns_total` | none |
| `fleet_prober_probes_in_flight` / `fleet_prober_probe_concurrency` | none |

`process_open_fds` and the other `process_*` metrics come with prometheus-client.

There are no per-server labels: they would mean IP or PII concerns plus high cardinality, and
the api already holds per-server health.

## Scale & robustness

**Cycle time.** The probes are paced: the 5 samples of a probe go out 50 ms apart and each
has its own timeout, so a live server costs about `4 × gap + RTT` (~0.3 s) and a dead,
blackholed one `4 × gap + timeout` (1.2 s), not `5 × timeout` (5.2 s). With the default
concurrency of 256 a 2,000-server fleet takes about 5 s, a third of the 15 s interval.
Rough sizing: `cycle ≈ (live × 0.35 s + dead × 1.2 s) / PROBE_CONCURRENCY`.

**File descriptors.** One server's probe holds at most `PROBE_SAMPLES + 2` sockets (1 UDP,
5 TCP, 1 HTTP), so 256 concurrent servers need up to ~1,800. At start the prober raises its
soft `RLIMIT_NOFILE` to the hard limit and, if `PROBE_CONCURRENCY` still would not fit, caps
it (logged, and exported as `fleet_prober_probe_concurrency`). Compose sets `nofile` to 65536.

**Correct RTTs under load.** With hundreds of probes on one event loop, a timestamp taken in
a callback is late by however long the loop took to get there. On Linux the prober uses the
kernel's numbers instead: `SO_TIMESTAMPNS` receive timestamps for UDP echoes, and the
handshake RTT the TCP stack measured (`TCP_INFO.tcpi_rtt`) for connects. Measured against
simulated nodes at concurrency 256, the median p50 error went from +28.6 ms (loop timestamps)
to +1.8 ms. A test blocks the loop for 200 ms during a probe and checks that RTTs stay small.

**Sharding.** `PROBER_SHARD=i/N` keeps the servers with `sha256(id) mod N == i`. Run N
replicas with `PROBER_SHARD=0/N … (N-1)/N` and distinct `PROBER_ID`s: each server is probed
by exactly one of them, with no coordination. Changing N reshuffles the assignment, which is
harmless because the prober holds no per-server state (the api's hysteresis does). For
redundancy across regions, run one full set of shards per region; the api accepts heartbeats
from several probers. If a shard's prober dies, its servers go unhealthy after the api's 90 s
staleness rule, so run each shard under a supervisor (Deployment/StatefulSet, restart policy).

**Measured** with `tools/fleet_sim.py` (one process: live nodes on 127.1.x.y with 5-150 ms
UDP echo delay and 2% loss, blackholed nodes on TEST-NET-2 that time out, and a fake api that
verifies HMAC, the 1 MiB body limit and the 5,000-result limit) and `tools/scale_probe.py`
(runs real cycles with the production wiring), on a shared 2-vCPU sandbox:

| | before (concurrency 32, sequential samples, httpx) | after (defaults) |
|---|---|---|
| 1,100 servers (100 dead) | 41-52 s per cycle (42 s even at concurrency 256), 5.3 s CPU | 3.2-4.3 s, 1.6 s CPU |
| 2,000 servers (200 dead) | not run (extrapolates to > 75 s) | 5.0-5.5 s per cycle, ~3 s CPU, 5 cycles in a row |
| heartbeat POSTs, 2,000 servers | 1 × 2,000 results | 4 × ≤ 500 results, largest body 64 KiB |
| peak / after-cycle fds | 72 / 8 | ≤ 1,050 / 8 (no leaked sockets, 0 leftover tasks) |
| RSS | 50 MB | 57-60 MB, flat across cycles |
| RTT p50 error vs simulator | median +4 ms at c=32, +167 ms at c=256 | median +2.0 ms, p99 +12 ms (simulator jitter is ±10%) |
| 2 shards (0/2, 1/2) | n/a | 975 + 1,025 servers, disjoint, union is the whole fleet |
| SIGTERM mid-cycle | | cycle finished and posted, exit 0 in 2.2 s |

```bash
python tools/fleet_sim.py --nodes 1800 --dead 200 --api-port 18099 &   # ~3 fds per node
API_URL=http://127.0.0.1:18099 PROBER_SERVICE_SECRET=sim-prober-secret \
  python tools/scale_probe.py --cycles 5            # add --shard 0/2, --concurrency N
```

## Run

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/pytest -q                       # tests
.venv/bin/ruff check . && .venv/bin/mypy           # mypy --strict on src and tools

# Offline demo: two fake nodes on loopback aliases, plus one server (127.0.0.4) that is down
.venv/bin/python tools/fake_node.py --host 127.0.0.2 --load 0.35 --delay-ms 12 &
.venv/bin/python tools/fake_node.py --host 127.0.0.3 --load 0.8 --drop 0.4 --delay-ms 25 &
.venv/bin/python -m fleet_prober --once --dry-run --servers-file examples/servers.local.json

# Against a real api
API_URL=http://localhost:8080 PROBER_ID=prober-eu-1 PROBER_SERVICE_SECRET=... \
  .venv/bin/python -m fleet_prober

# Docker
docker build -t fleet-prober . && docker run --rm -e API_URL=... -e PROBER_SERVICE_SECRET=... fleet-prober
```

`--once` runs a single cycle and prints the batch JSON on stdout (logs go to stderr).
`--dry-run` probes but does not POST. A secret is only optional when `--dry-run` is combined
with a servers file.

## Layout

```
src/fleet_prober/
  config.py    pydantic-settings env config
  models.py    wire models (Server, ServerResult, HeartbeatBatch)
  signing.py   HMAC v1 request signing (+ verify, used by tests)
  probes.py    paced UDP echo / TCP connect probes (kernel timestamps), minimal /load
               client, percentiles, result assembly
  client.py    signed api client with retry/backoff (and a deadline)
  runner.py    the loop: sharding, bounded concurrency, per-server deadline, chunked
               heartbeats, no overlapping cycles, jittered interval, graceful shutdown
  metrics.py   Prometheus metrics
  logs.py      JSON logging
tools/fake_node.py   local node simulator (UDP echo, TCP listener, HTTP /load)
tools/fleet_sim.py   thousands of fake nodes + a contract-checking fake api, one process
tools/scale_probe.py runs real cycles against fleet_sim and reports time, fds, RTT error
tests/               pytest: signing vectors, probes against real local sockets,
                     runner against a contract-enforcing fake api
```
