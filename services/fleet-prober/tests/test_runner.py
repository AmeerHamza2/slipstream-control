"""Runner + ApiClient against a fake api (httpx.MockTransport) that enforces the contract."""

from __future__ import annotations

import asyncio
import json
import re
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx
import pytest
from prometheus_client import REGISTRY

from fleet_prober import runner as runner_mod
from fleet_prober import signing
from fleet_prober.client import ApiClient, ApiError, backoff_delay
from fleet_prober.models import HeartbeatBatch, Server, ServerResult
from fleet_prober.probes import ProbeConfig
from fleet_prober.runner import CycleInProgressError, Runner, Shard
from tests.conftest import Node, free_port

SECRET = b"prober-secret"
RFC3339_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


@dataclass
class FakeApi:
    servers: list[dict[str, object]]
    fail_heartbeats: int = 0  # respond 500 this many times first
    requests: list[httpx.Request] = field(default_factory=list)
    batches: list[dict[str, object]] = field(default_factory=list)

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        body = request.content
        if request.headers.get("X-Slipstream-Service") != "fleet-prober" or not signing.verify(
            SECRET, dict(request.headers), request.method, request.url.path, body
        ):
            return httpx.Response(401, json={"error": {"code": "unauthorized"}})
        if request.method == "GET" and request.url.path == "/internal/v1/servers":
            return httpx.Response(200, json=self.servers)
        if request.method == "POST" and request.url.path == "/internal/v1/servers/heartbeats":
            if self.fail_heartbeats > 0:
                self.fail_heartbeats -= 1
                return httpx.Response(500, json={"error": {"code": "internal"}})
            batch = json.loads(body)
            self.batches.append(batch)
            return httpx.Response(202, json={"accepted": len(batch["results"])})
        return httpx.Response(404, json={"error": {"code": "not_found"}})


def make_api(
    handler: Callable[[httpx.Request], httpx.Response], sleeps: list[float], secret: bytes = SECRET
) -> ApiClient:
    async def fake_sleep(s: float) -> None:
        sleeps.append(s)

    http = httpx.AsyncClient(base_url="http://api.test", transport=httpx.MockTransport(handler))
    return ApiClient(
        http, secret, attempts=4, backoff_base_s=0.5, backoff_max_s=4, sleep=fake_sleep
    )


def server_json(i: int, **kw: object) -> dict[str, object]:
    return {
        "id": f"00000000-0000-4000-8000-00000000000{i}",
        "name": f"fra-0{i}",
        "public_ipv4": "127.0.0.1",
        "wg_port": 51820,
        "ss_port": 8443,
        "country": "DE",
        **kw,
    }  # extra field must be tolerated


async def stub_probe(server: Server, _cfg: ProbeConfig) -> ServerResult:
    return ServerResult(
        server_id=server.id, reachable=True, rtt_ms_p50=41.5, rtt_ms_p95=63.0, loss=0.0, load=0.35
    )


def make_runner(api: ApiClient, probe=stub_probe, **kw: object) -> Runner:  # type: ignore[no-untyped-def]
    kw.setdefault("interval_s", 60.0)  # also the post-retry deadline; tests fake the sleeps
    kw.setdefault("concurrency", 2)
    return Runner(
        prober_id="prober-eu-1",
        api=api,
        probe_cfg=ProbeConfig(),
        probe=probe,
        **kw,
    )


async def test_cycle_signs_requests_and_posts_contract_payload() -> None:
    fake = FakeApi(servers=[server_json(1), server_json(2)])
    runner = make_runner(make_api(fake, []))

    await runner.run_cycle()

    get, post = fake.requests
    for req in (get, post):
        assert set(req.headers) >= {
            "x-slipstream-service",
            "x-slipstream-timestamp",
            "x-slipstream-signature",
            "x-request-id",
        }
        assert re.fullmatch(r"v1=[0-9a-f]{64}", req.headers["X-Slipstream-Signature"])
    assert post.headers["Content-Type"] == "application/json"

    (batch,) = fake.batches
    assert set(batch) == {"prober_id", "observed_at", "results"}
    assert batch["prober_id"] == "prober-eu-1"
    assert RFC3339_Z.match(batch["observed_at"])  # type: ignore[arg-type]
    assert batch["results"] == [
        {
            "server_id": f"00000000-0000-4000-8000-00000000000{i}",
            "reachable": True,
            "rtt_ms_p50": 41.5,
            "rtt_ms_p95": 63.0,
            "loss": 0.0,
            "load": 0.35,
        }
        for i in (1, 2)
    ]


async def test_retries_500_with_backoff_then_succeeds() -> None:
    fake = FakeApi(servers=[server_json(1)], fail_heartbeats=2)
    sleeps: list[float] = []
    await make_runner(make_api(fake, sleeps)).run_cycle()

    posts = [r for r in fake.requests if r.method == "POST"]
    assert len(posts) == 3 and len(fake.batches) == 1
    assert len(sleeps) == 2
    assert 0 <= sleeps[0] <= 0.5 and 0 <= sleeps[1] <= 1.0  # full jitter, doubling cap
    # Every attempt is freshly signed and keeps the same request id.
    assert len({p.headers["X-Request-Id"] for p in posts}) == 1


async def test_gives_up_after_max_attempts() -> None:
    fake = FakeApi(servers=[server_json(1)], fail_heartbeats=99)
    with pytest.raises(ApiError, match="after 4 attempts"):
        await make_runner(make_api(fake, [])).run_cycle()
    assert sum(r.method == "POST" for r in fake.requests) == 4


async def test_network_errors_are_retried() -> None:
    calls = 0

    def flaky(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise httpx.ConnectError("boom", request=request)
        return httpx.Response(200, json=[server_json(1)])

    sleeps: list[float] = []
    servers = await make_api(flaky, sleeps).get_servers()
    assert calls == 2 and len(sleeps) == 1 and servers[0].name == "fra-01"


async def test_4xx_is_not_retried() -> None:
    fake = FakeApi(servers=[])
    with pytest.raises(ApiError) as err:
        await make_api(fake, [], secret=b"wrong-secret").get_servers()
    assert err.value.status == 401 and len(fake.requests) == 1


def test_backoff_is_capped() -> None:
    assert all(0 <= backoff_delay(10, 0.5, 4.0) <= 4.0 for _ in range(100))


async def test_one_failing_probe_does_not_sink_the_batch() -> None:
    async def sometimes_broken(s: Server, cfg: ProbeConfig) -> ServerResult:
        if s.name == "fra-02":
            raise RuntimeError("bug")
        return await stub_probe(s, cfg)

    fake = FakeApi(servers=[server_json(1), server_json(2), server_json(3)])
    await make_runner(make_api(fake, []), probe=sometimes_broken).run_cycle()
    assert [r["server_id"][-1] for r in fake.batches[0]["results"]] == ["1", "3"]  # type: ignore[index]


async def test_concurrency_is_bounded() -> None:
    active = peak = 0

    async def slow(s: Server, cfg: ProbeConfig) -> ServerResult:
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.01)
        active -= 1
        return await stub_probe(s, cfg)

    fake = FakeApi(servers=[server_json(i) for i in range(1, 8)])
    await make_runner(make_api(fake, []), probe=slow).run_cycle()
    assert peak == 2 and len(fake.batches[0]["results"]) == 7  # type: ignore[arg-type]


async def test_run_forever_survives_failures_and_stops_on_event() -> None:
    fake = FakeApi(servers=[server_json(1)], fail_heartbeats=4)  # first cycle exhausts retries
    runner = make_runner(make_api(fake, []), interval_s=0.05)
    stop = asyncio.Event()
    task = asyncio.create_task(runner.run_forever(stop))
    for _ in range(200):
        if fake.batches:
            break
        await asyncio.sleep(0.01)
    stop.set()
    await asyncio.wait_for(task, 1.0)
    assert fake.batches, "loop kept going after a failed cycle"


async def test_real_probes_through_runner(node: Node) -> None:
    """Full path: signed GET -> real UDP/TCP/HTTP probes -> signed POST."""
    up = server_json(1, wg_port=node.udp_port - 1, ss_port=node.tcp_port)
    down = server_json(2, wg_port=free_port() - 1, ss_port=free_port())
    fake = FakeApi(servers=[up, down])
    runner = Runner(
        prober_id="prober-eu-1",
        api=make_api(fake, []),
        probe_cfg=ProbeConfig(
            samples=3, timeout_s=0.2, gap_s=0, load_port=node.http_port, load_timeout_s=0.2
        ),
        concurrency=4,
        interval_s=1,
    )
    await runner.run_cycle()
    r_up, r_down = fake.batches[0]["results"]  # type: ignore[misc]
    assert r_up["reachable"] is True and r_up["loss"] == 0.0 and r_up["load"] == 0.35
    assert r_down == {
        "server_id": down["id"],
        "reachable": False,
        "rtt_ms_p50": None,
        "rtt_ms_p95": None,
        "loss": 1.0,
        "load": 0.35,
    }


# ------------------------------------------------------------------ scale & robustness


def many(n: int) -> list[dict[str, object]]:
    return [
        {**server_json(1), "id": str(uuid.UUID(int=i + 1, version=4)), "name": f"s-{i}"}
        for i in range(n)
    ]


async def test_heartbeats_are_chunked_under_the_api_limits() -> None:
    fake = FakeApi(servers=many(1_234))
    runner = make_runner(make_api(fake, []), concurrency=64)
    batch = await runner.run_cycle()
    assert [len(b["results"]) for b in fake.batches] == [500, 500, 234]  # type: ignore[arg-type]
    assert len({b["observed_at"] for b in fake.batches}) == 1
    posted = [r["server_id"] for b in fake.batches for r in b["results"]]  # type: ignore[attr-defined]
    assert sorted(posted) == sorted(r.server_id for r in batch.results)
    for req in fake.requests:
        assert len(req.content) < 1 << 20


async def test_chunks_also_split_by_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner_mod, "MAX_HEARTBEAT_BODY", 4_000)
    fake = FakeApi(servers=many(100))
    await make_runner(make_api(fake, []), batch_size=500).run_cycle()
    assert len(fake.batches) > 1
    assert all(len(json.dumps(b)) <= 4_000 for b in fake.batches)
    assert sum(len(b["results"]) for b in fake.batches) == 100  # type: ignore[arg-type,misc]


async def test_a_failed_chunk_does_not_stop_the_others() -> None:
    fake = FakeApi(servers=many(1_200), fail_heartbeats=4)  # exhausts the first chunk only
    with pytest.raises(ApiError, match="1/3 heartbeat posts failed"):
        await make_runner(make_api(fake, []), concurrency=64).run_cycle()
    assert [len(b["results"]) for b in fake.batches] == [500, 200]  # type: ignore[arg-type]


async def test_post_retries_stop_at_the_cycle_deadline() -> None:
    fake = FakeApi(servers=[], fail_heartbeats=99)
    api = make_api(fake, [])
    batch = HeartbeatBatch(prober_id="p", observed_at=datetime.now(UTC), results=[])
    with pytest.raises(ApiError, match="deadline"):
        await api.post_heartbeats(batch, deadline=time.monotonic() + 0.001)
    assert sum(r.method == "POST" for r in fake.requests) == 1


def test_shards_partition_the_fleet() -> None:
    ids = [str(uuid.uuid4()) for _ in range(3_000)]
    shards = [Shard.parse(f"{i}/3") for i in range(3)]
    owners = [[s.owns(i) for s in shards].count(True) for i in ids]
    assert owners == [1] * len(ids)  # every server exactly once
    sizes = [sum(s.owns(i) for i in ids) for s in shards]
    assert all(800 < n < 1_200 for n in sizes), sizes
    assert shards[0].owns(ids[0].upper()) == shards[0].owns(ids[0])  # case-insensitive
    assert Shard.parse("0/1").owns("anything")
    for bad in ("3/3", "1/0", "x", "1/2/3", "-1/2"):
        with pytest.raises(ValueError):
            Shard.parse(bad)


async def test_runner_probes_only_its_shard() -> None:
    fake = FakeApi(servers=many(300))
    seen: list[set[str]] = []
    for i in range(2):
        await make_runner(make_api(fake, []), shard=Shard(i, 2), concurrency=32).run_cycle()
        seen.append({r["server_id"] for r in fake.batches[-1]["results"]})  # type: ignore[attr-defined]
    assert not seen[0] & seen[1]
    assert len(seen[0] | seen[1]) == 300


async def test_cycles_never_overlap() -> None:
    gate = asyncio.Event()

    async def blocked(s: Server, cfg: ProbeConfig) -> ServerResult:
        await gate.wait()
        return await stub_probe(s, cfg)

    runner = make_runner(make_api(FakeApi(servers=[server_json(1)]), []), probe=blocked)
    first = asyncio.create_task(runner.run_cycle())
    await asyncio.sleep(0.01)
    with pytest.raises(CycleInProgressError):
        await runner.run_cycle()
    gate.set()
    await first


async def test_a_hung_probe_is_cut_off_and_overruns_are_counted() -> None:
    async def hangs(s: Server, cfg: ProbeConfig) -> ServerResult:
        if s.name == "fra-02":
            await asyncio.sleep(3600)
        return await stub_probe(s, cfg)

    before = metric("fleet_prober_cycle_overruns_total")
    fake = FakeApi(servers=[server_json(1), server_json(2)])
    runner = make_runner(make_api(fake, []), probe=hangs, server_deadline_s=0.1, interval_s=0.05)
    t0 = time.monotonic()
    batch = await runner.run_cycle()
    assert time.monotonic() - t0 < 1.0
    assert [r.server_id[-1] for r in batch.results] == ["1"]
    assert metric("fleet_prober_cycle_overruns_total") == before + 1
    assert metric("fleet_prober_fleet_servers") == 2
    assert metric("fleet_prober_probes_in_flight") == 0


def metric(name: str) -> float:
    value = REGISTRY.get_sample_value(name)
    assert value is not None, name
    return value
