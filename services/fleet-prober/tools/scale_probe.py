"""Scale harness: run several real prober cycles against tools/fleet_sim.py and report.

    python tools/fleet_sim.py --nodes 1000 --dead 100 &
    python tools/scale_probe.py --cycles 3 [--concurrency N] [--shard 0/2]

Uses the same Settings/env and wiring as `python -m fleet_prober`, then prints one JSON
line per cycle (duration, fds, tasks, RSS, CPU) and a summary that compares measured
RTTs with the simulator's configured per-node delays and checks the api's view.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import resource
import statistics
import time
from typing import Any

import httpx

from fleet_prober import signing
from fleet_prober.__main__ import build_runner
from fleet_prober.config import Settings


def _fds() -> int:
    return len(os.listdir("/proc/self/fd"))


def _rss_mb() -> float:
    with open("/proc/self/status") as f:
        for line in f:
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) / 1024
    return float("nan")


async def _sim_servers(base: str, secret: bytes) -> list[dict[str, Any]]:
    path = "/internal/v1/servers"
    async with httpx.AsyncClient(base_url=base) as c:
        r = await c.get(path, headers=signing.sign(secret, "GET", path))
        r.raise_for_status()
        data: list[dict[str, Any]] = r.json()
        return data


async def main_async(args: argparse.Namespace) -> int:
    overrides: dict[str, Any] = {"metrics_port": 0}
    if args.concurrency:
        overrides["probe_concurrency"] = args.concurrency
    if args.shard:
        overrides["prober_shard"] = args.shard
    settings = Settings(**overrides)
    secret = settings.prober_service_secret.get_secret_value().encode()
    fd_peak = 0
    stop_sampling = asyncio.Event()

    async def sample_fds() -> None:
        nonlocal fd_peak
        while not stop_sampling.is_set():
            fd_peak = max(fd_peak, _fds())
            await asyncio.sleep(0.05)

    sampler = asyncio.create_task(sample_fds())
    batch = None
    async with build_runner(settings, secret) as runner:
        for i in range(args.cycles):
            fd_peak = 0
            cpu0 = time.process_time()
            t0 = time.monotonic()
            batch = await runner.run_cycle(post=True)
            dt = time.monotonic() - t0
            await asyncio.sleep(0.3)  # let closed sockets settle before counting
            print(
                json.dumps(
                    {
                        "cycle": i + 1,
                        "servers": len(batch.results),
                        "reachable": sum(r.reachable for r in batch.results),
                        "duration_s": round(dt, 2),
                        "cpu_s": round(time.process_time() - cpu0, 2),
                        "fd_peak": fd_peak,
                        "fd_after": _fds(),
                        "tasks_after": len(asyncio.all_tasks()) - 2,  # minus main + sampler
                        "rss_mb": round(_rss_mb(), 1),
                    }
                ),
                flush=True,
            )
    stop_sampling.set()
    await sampler

    assert batch is not None
    sim = {s["id"]: s for s in await _sim_servers(settings.api_url, secret)}
    errs: list[float] = []
    wrong: list[str] = []
    for r in batch.results:
        s = sim[r.server_id]
        expected = s.get("sim_delay_ms")
        if expected is None:  # blackholed
            if r.reachable:
                wrong.append(f"dead {r.server_id} reported reachable")
            continue
        if not r.reachable or r.rtt_ms_p50 is None:
            wrong.append(f"live {r.server_id} reported unreachable")
            continue
        errs.append(r.rtt_ms_p50 - float(expected))
    async with httpx.AsyncClient(base_url=settings.api_url) as c:
        api_stats = (await c.get("/stats")).json()
    errs.sort()
    summary = {
        "summary": True,
        "fleet": len(sim),
        "reported": len(batch.results),
        "misclassified": len(wrong),
        "rtt_p50_error_ms": {
            "median": round(statistics.median(errs), 2) if errs else None,
            "p99": round(errs[int(0.99 * (len(errs) - 1))], 2) if errs else None,
            "max": round(errs[-1], 2) if errs else None,
        },
        "nofile_limit": resource.getrlimit(resource.RLIMIT_NOFILE)[0],
        "api": api_stats,
    }
    print(json.dumps(summary), flush=True)
    for w in wrong[:5]:
        print(w)
    return 1 if wrong else 0


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--cycles", type=int, default=3)
    p.add_argument("--concurrency", type=int, default=0, help="override PROBE_CONCURRENCY")
    p.add_argument("--shard", default="", help="override PROBER_SHARD, e.g. 0/2")
    raise SystemExit(asyncio.run(main_async(p.parse_args())))


if __name__ == "__main__":
    main()
