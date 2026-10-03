"""Prometheus metrics, served on :9101 (docs/CONTRACT.md, "Fleet prober").

Labels deliberately exclude server IPs (logging/PII rule) and server ids (cardinality);
per-server health lives in the api, which is the source of truth for it.
"""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram, start_http_server

PROBE_SAMPLES = Counter(
    "fleet_prober_probe_samples_total",
    "Individual probe samples sent, by probe kind and outcome.",
    ["kind", "outcome"],  # kind: tcp|udp ; outcome: ok|timeout|error
)
PROBE_RTT = Histogram(
    "fleet_prober_probe_rtt_seconds",
    "Round-trip time of successful probe samples.",
    ["kind"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.15, 0.25, 0.4, 0.6, 1.0, 2.0),
)
SERVERS_PROBED = Counter(
    "fleet_prober_servers_probed_total",
    "Servers probed, by result.",
    ["result"],  # reachable|unreachable|error
)
CYCLE_DURATION = Histogram(
    "fleet_prober_cycle_duration_seconds",
    "Wall time of a full fetch-probe-report cycle.",
    buckets=(0.5, 1, 2, 3, 5, 8, 13, 20, 30, 60),
)
CYCLES = Counter("fleet_prober_cycles_total", "Probe cycles, by outcome.", ["outcome"])
API_REQUESTS = Counter(
    "fleet_prober_api_requests_total",
    "Requests to the internal api, by endpoint and outcome.",
    ["endpoint", "outcome"],  # outcome: 2xx|4xx|5xx|network
)
FLEET_LISTED = Gauge("fleet_prober_fleet_listed", "Servers in the most recent fleet listing.")
FLEET_SIZE = Gauge(
    "fleet_prober_fleet_servers", "Servers this prober owns (after PROBER_SHARD) last cycle."
)
FLEET_REACHABLE = Gauge("fleet_prober_fleet_reachable", "Reachable servers in the last cycle.")
LAST_SUCCESS = Gauge(
    "fleet_prober_last_success_timestamp_seconds",
    "Unix time of the last heartbeat batch accepted by the api.",
)

LAST_CYCLE = Gauge(
    "fleet_prober_last_cycle_timestamp_seconds",
    "Unix time the last cycle finished (successfully or not); the liveness signal.",
)
CYCLE_OVERRUNS = Counter(
    "fleet_prober_cycle_overruns_total", "Cycles that took longer than PROBE_INTERVAL_S."
)
PROBES_IN_FLIGHT = Gauge("fleet_prober_probes_in_flight", "Servers being probed right now.")
PROBE_CONCURRENCY = Gauge(
    "fleet_prober_probe_concurrency", "Effective probe concurrency (after the fd budget)."
)


def serve(port: int) -> None:
    """Start the metrics HTTP server in a background thread (no-op when port is 0)."""
    if port:
        start_http_server(port)
