"""CLI entry point: `python -m fleet_prober [--once] [--dry-run] [--servers-file PATH]`."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import resource
import signal
import sys
import time
import urllib.request
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
from pydantic import ValidationError

from fleet_prober import __version__, logs, metrics
from fleet_prober.client import ApiClient, ApiError
from fleet_prober.config import Settings
from fleet_prober.models import Server, ServerList
from fleet_prober.probes import ProbeConfig, fds_per_server
from fleet_prober.runner import FetchServers, Runner, Shard

log = logging.getLogger("fleet_prober")


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="fleet-prober", description=__doc__)
    p.add_argument("--once", action="store_true", help="run a single cycle and print the batch")
    p.add_argument("--dry-run", action="store_true", help="probe but do not POST heartbeats")
    p.add_argument("--servers-file", type=Path, help="read servers from JSON instead of the api")
    p.add_argument(
        "--healthcheck",
        action="store_true",
        help="exit 0 if the local prober finished a cycle recently (container HEALTHCHECK)",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p.parse_args(argv)


def _file_source(path: Path) -> FetchServers:
    async def fetch() -> list[Server]:
        return ServerList.validate_json(await asyncio.to_thread(path.read_bytes))

    return fetch


# Sockets outside the probes: api pool, metrics server, stdio, Python itself.
FD_RESERVE = 64


def raise_nofile_limit() -> int:
    """Raise the soft open-file limit to the hard limit; return the resulting soft limit."""
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if hard == resource.RLIM_INFINITY or hard > soft:
        target = hard if hard != resource.RLIM_INFINITY else max(soft, 1 << 20)
        with contextlib.suppress(ValueError, OSError):
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
            soft = target
    return soft


def effective_concurrency(settings: Settings) -> int:
    """PROBE_CONCURRENCY capped so the worst case (every probe socket open) fits the fd limit."""
    soft = raise_nofile_limit()
    per_server = fds_per_server(settings.probe_samples)
    budget = max(1, (soft - FD_RESERVE) // per_server)
    if settings.probe_concurrency > budget:
        log.warning(
            "PROBE_CONCURRENCY capped by the open-file limit",
            extra={
                "configured": settings.probe_concurrency,
                "effective": budget,
                "nofile": soft,
                "fds_per_server": per_server,
            },
        )
        return budget
    return settings.probe_concurrency


@contextlib.asynccontextmanager
async def build_runner(settings: Settings, secret: bytes) -> AsyncIterator[Runner]:
    """The production wiring: api client, node HTTP pool and Runner (also used by tools/)."""
    async with httpx.AsyncClient(
        base_url=settings.api_url, timeout=settings.http_timeout_s
    ) as api_http:
        api = ApiClient(
            api_http,
            secret,
            attempts=settings.retry_attempts,
            backoff_base_s=settings.retry_base_s,
            backoff_max_s=settings.retry_max_s,
        )
        yield Runner(
            prober_id=settings.prober_id,
            api=api,
            probe_cfg=ProbeConfig(
                samples=settings.probe_samples,
                timeout_s=settings.probe_timeout_s,
                gap_s=settings.probe_sample_gap_s,
                load_port=settings.load_port,
                load_timeout_s=settings.load_timeout_s,
            ),
            concurrency=effective_concurrency(settings),
            interval_s=settings.probe_interval_s,
            interval_jitter=settings.interval_jitter,
            fetch_servers=_file_source(settings.servers_file) if settings.servers_file else None,
            shard=Shard.parse(settings.prober_shard),
            batch_size=settings.heartbeat_batch_size,
        )


async def _amain(settings: Settings, *, once: bool, dry_run: bool) -> int:
    secret = settings.prober_service_secret.get_secret_value().encode()
    needs_api = not (dry_run and settings.servers_file)
    if needs_api and not secret:
        log.error("PROBER_SERVICE_SECRET is required unless using --dry-run with a servers file")
        return 2

    async with build_runner(settings, secret) as runner:
        if once:
            try:
                batch = await runner.run_cycle(post=not dry_run)
            except (ApiError, ValidationError, OSError) as exc:
                log.error("cycle failed", extra={"error": f"{type(exc).__name__}: {exc}"})
                return 1
            print(batch.model_dump_json(indent=2))
            return 0

        metrics.serve(settings.metrics_port)
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, stop.set)
        await runner.run_forever(stop, post=not dry_run)
        return 0


def healthcheck(settings: Settings) -> int:
    """Liveness via the local metrics endpoint: a cycle finished within 3 intervals.

    "Finished" includes failed cycles (api down): that is the api's problem, and
    restarting the prober would not fix it. A wedged loop is what this catches.
    """
    if not settings.metrics_port:
        return 0  # nothing to ask; rely on the process being alive
    max_age = 3 * settings.probe_interval_s + 30
    try:
        url = f"http://127.0.0.1:{settings.metrics_port}/metrics"
        with urllib.request.urlopen(url, timeout=3) as resp:
            text = resp.read().decode()
    except OSError:
        return 1
    last = _metric(text, "fleet_prober_last_cycle_timestamp_seconds")
    if last is None:
        return 1
    # Before the first cycle the gauge is 0: measure from process start instead.
    reference = float(last) or float(_metric(text, "process_start_time_seconds") or 0)
    return 0 if time.time() - reference <= max_age else 1


def _metric(text: str, name: str) -> str | None:
    for line in text.splitlines():
        if line.startswith(name + " "):
            return line.split()[1]
    return None


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        settings = Settings()
    except ValidationError as exc:
        print(f"invalid configuration:\n{exc}", file=sys.stderr)
        return 2
    if args.healthcheck:
        return healthcheck(settings)
    if args.servers_file:
        settings = settings.model_copy(update={"servers_file": args.servers_file})
    logs.configure(settings.log_level)
    return asyncio.run(_amain(settings, once=args.once, dry_run=args.dry_run))


if __name__ == "__main__":
    sys.exit(main())
