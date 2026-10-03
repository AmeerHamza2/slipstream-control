"""The probe loop: fetch fleet -> (shard) -> probe concurrently -> post heartbeat batches."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import random
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from fleet_prober import metrics
from fleet_prober.client import ApiClient, ApiError
from fleet_prober.models import HeartbeatBatch, Server, ServerResult
from fleet_prober.probes import ProbeConfig, probe_server

log = logging.getLogger(__name__)

FetchServers = Callable[[], Awaitable[list[Server]]]
ProbeFn = Callable[[Server, ProbeConfig], Awaitable[ServerResult]]

# The api accepts heartbeat bodies up to 1 MiB (and at most 5,000 results). One result is
# ~130 bytes of JSON, so 500 per POST is ~65 KiB; the byte check below is a backstop.
MAX_HEARTBEAT_BODY = 1 << 20
DEFAULT_BATCH_SIZE = 500


@dataclass(frozen=True, slots=True)
class Shard:
    """`PROBER_SHARD=i/N`: this prober owns the servers whose id hashes to i (mod N).

    The hash is SHA-256 of the lower-cased id, so every prober agrees on the split without
    talking to each other, and the split is stable for a given N.
    """

    index: int
    count: int

    @classmethod
    def parse(cls, spec: str) -> Shard:
        try:
            i, n = (int(x) for x in spec.split("/"))
        except ValueError:
            raise ValueError(f"shard must look like i/N, got {spec!r}") from None
        if n < 1 or not 0 <= i < n:
            raise ValueError(f"shard index must be in 0..N-1, got {spec!r}")
        return cls(i, n)

    def owns(self, server_id: str) -> bool:
        if self.count == 1:
            return True
        h = hashlib.sha256(server_id.lower().encode()).digest()
        return int.from_bytes(h[:8], "big") % self.count == self.index

    def __str__(self) -> str:
        return f"{self.index}/{self.count}"


class CycleInProgressError(RuntimeError):
    """run_cycle was called while another cycle is still running (never overlap)."""


class Runner:
    def __init__(
        self,
        *,
        prober_id: str,
        api: ApiClient,
        probe_cfg: ProbeConfig,
        concurrency: int,
        interval_s: float,
        interval_jitter: float = 0.1,
        fetch_servers: FetchServers | None = None,
        probe: ProbeFn = probe_server,
        shutdown_grace_s: float = 10.0,
        shard: Shard | None = None,
        batch_size: int = DEFAULT_BATCH_SIZE,
        server_deadline_s: float | None = None,
    ) -> None:
        self._prober_id = prober_id
        self._api = api
        self._probe_cfg = probe_cfg
        self._sem = asyncio.Semaphore(concurrency)
        self._interval = interval_s
        self._jitter = interval_jitter
        self._fetch_servers = fetch_servers or api.get_servers
        self._probe = probe
        self._grace = shutdown_grace_s
        self._shard = shard or Shard(0, 1)
        self._batch_size = max(1, batch_size)
        # Hard per-server ceiling: a probe that somehow outlives its own timeouts must not
        # hold a concurrency slot (and the cycle) hostage.
        self._server_deadline_s = server_deadline_s or probe_cfg.worst_case_s + 2.0
        self._cycle_lock = asyncio.Lock()
        metrics.PROBE_CONCURRENCY.set(concurrency)

    async def _probe_one(self, server: Server) -> ServerResult | None:
        async with self._sem:
            metrics.PROBES_IN_FLIGHT.inc()
            try:
                async with asyncio.timeout(self._server_deadline_s):
                    result = await self._probe(server, self._probe_cfg)
            except Exception as exc:
                # A bug probing one server must not sink the batch. We omit it rather than
                # report "unreachable": a prober fault is not evidence the node is down, and
                # the api already marks servers with no heartbeat for 90 s as unhealthy.
                metrics.SERVERS_PROBED.labels(result="error").inc()
                # Error type only: messages/tracebacks may embed the node's IP (log policy).
                log.error(
                    "probe failed", extra={"server_id": server.id, "error": type(exc).__name__}
                )
                return None
            finally:
                metrics.PROBES_IN_FLIGHT.dec()
        metrics.SERVERS_PROBED.labels(
            result="reachable" if result.reachable else "unreachable"
        ).inc()
        return result

    async def probe_fleet(self) -> HeartbeatBatch:
        listed = await self._fetch_servers()
        servers = [s for s in listed if self._shard.owns(s.id)]
        metrics.FLEET_LISTED.set(len(listed))
        metrics.FLEET_SIZE.set(len(servers))
        outcomes = await asyncio.gather(*(self._probe_one(s) for s in servers))
        results = [r for r in outcomes if r is not None]
        metrics.FLEET_REACHABLE.set(sum(r.reachable for r in results))
        return HeartbeatBatch(
            prober_id=self._prober_id, observed_at=datetime.now(UTC), results=results
        )

    def chunks(self, batch: HeartbeatBatch) -> list[HeartbeatBatch]:
        """Split a batch into POST-sized pieces (<= batch_size results, < 1 MiB each)."""
        out: list[HeartbeatBatch] = []
        pending = [
            batch.results[i : i + self._batch_size]
            for i in range(0, len(batch.results), self._batch_size)
        ]
        while pending:
            part = pending.pop(0)
            chunk = batch.model_copy(update={"results": part})
            if len(part) > 1 and len(chunk.model_dump_json()) > MAX_HEARTBEAT_BODY * 0.9:
                half = len(part) // 2
                pending[:0] = [part[:half], part[half:]]
                continue
            out.append(chunk)
        return out

    async def _post(self, batch: HeartbeatBatch, deadline: float) -> None:
        chunks = self.chunks(batch)
        accepted = 0
        failures: list[BaseException] = []
        for chunk in chunks:
            # Keep going after a failed chunk: the other servers' heartbeats are still good.
            try:
                resp = await self._api.post_heartbeats(chunk, deadline=deadline)
                accepted += int(resp.get("accepted", 0))
            except ApiError as exc:
                failures.append(exc)
        log.info(
            "heartbeats posted",
            extra={
                "accepted": accepted,
                "results": len(batch.results),
                "posts": len(chunks),
                "failed_posts": len(failures),
            },
        )
        if failures:
            raise ApiError(
                f"{len(failures)}/{len(chunks)} heartbeat posts failed (last: {failures[-1]})"
            )
        metrics.LAST_SUCCESS.set(time.time())

    async def run_cycle(self, *, post: bool = True) -> HeartbeatBatch:
        """One full cycle. Raises on fetch/post failure (after retries)."""
        if self._cycle_lock.locked():
            raise CycleInProgressError("a probe cycle is already running")
        async with self._cycle_lock:
            return await self._run_cycle(post=post)

    async def _run_cycle(self, *, post: bool) -> HeartbeatBatch:
        start = time.monotonic()
        try:
            batch = await self.probe_fleet()
            if post:
                if batch.results:
                    # Retrying past the next cycle is pointless: it will carry fresher data.
                    await self._post(batch, deadline=start + self._interval)
                else:
                    log.info("no servers to report")
        except Exception:
            metrics.CYCLES.labels(outcome="error").inc()
            raise
        finally:
            elapsed = time.monotonic() - start
            metrics.CYCLE_DURATION.observe(elapsed)
            metrics.LAST_CYCLE.set(time.time())
            if elapsed > self._interval:
                metrics.CYCLE_OVERRUNS.inc()
                log.warning(
                    "cycle took longer than the interval; raise PROBE_CONCURRENCY or shard",
                    extra={"duration_s": round(elapsed, 3), "interval_s": self._interval},
                )
        metrics.CYCLES.labels(outcome="ok").inc()
        reachable = sum(r.reachable for r in batch.results)
        log.info(
            "cycle complete",
            extra={
                "servers": len(batch.results),
                "reachable": reachable,
                "shard": str(self._shard),
                "duration_s": round(time.monotonic() - start, 3),
            },
        )
        return batch

    def next_delay(self, elapsed: float) -> float:
        """Interval +/- jitter, measured from cycle start, so probers don't sync up."""
        target = self._interval * (1.0 + random.uniform(-self._jitter, self._jitter))
        return max(0.0, target - elapsed)

    async def run_forever(self, stop: asyncio.Event, *, post: bool = True) -> None:
        log.info(
            "prober started", extra={"prober_id": self._prober_id, "interval_s": self._interval}
        )
        while not stop.is_set():
            start = time.monotonic()
            await self._cycle_until_stopped(stop, post=post)
            if stop.is_set():
                break
            try:
                await asyncio.wait_for(
                    stop.wait(), timeout=self.next_delay(time.monotonic() - start)
                )
            except TimeoutError:
                pass
        log.info("prober stopped")

    async def _cycle_until_stopped(self, stop: asyncio.Event, *, post: bool) -> None:
        cycle = asyncio.create_task(self.run_cycle(post=post))
        stopper = asyncio.create_task(stop.wait())
        try:
            await asyncio.wait({cycle, stopper}, return_when=asyncio.FIRST_COMPLETED)
            if not cycle.done():
                log.info(
                    "shutdown requested, finishing in-flight cycle", extra={"grace_s": self._grace}
                )
                await asyncio.wait({cycle}, timeout=self._grace)
                if not cycle.done():
                    cycle.cancel()
            if cycle.done() and not cycle.cancelled() and (exc := cycle.exception()) is not None:
                log.error("cycle failed", extra={"error": f"{type(exc).__name__}: {exc}"})
        finally:
            stopper.cancel()
            if not cycle.done():
                cycle.cancel()
            await asyncio.gather(cycle, stopper, return_exceptions=True)
