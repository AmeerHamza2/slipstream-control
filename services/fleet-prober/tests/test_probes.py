import asyncio
import contextlib
import socket
import sys
import threading
import time

import pytest

from fleet_prober.models import Server
from fleet_prober.probes import (
    ProbeConfig,
    SampleStats,
    fds_per_server,
    fetch_load,
    percentile,
    probe_server,
    summarize,
    tcp_probe,
    udp_probe,
)
from tests.conftest import Node, free_port, start_node, stop_node

FAST = {"samples": 5, "timeout": 0.3}


def test_percentile_interpolates() -> None:
    assert percentile([], 50) is None
    assert percentile([7.0], 95) == 7.0
    assert percentile([1, 2, 3, 4, 5], 50) == 3
    assert percentile([10, 20, 30, 40, 50], 95) == pytest.approx(48.0)
    assert percentile([50, 10, 40, 20, 30], 95) == pytest.approx(48.0)  # order-independent


async def test_tcp_reachable(node: Node) -> None:
    stats = await tcp_probe(node.host, node.tcp_port, **FAST)
    assert stats.sent == 5 and stats.received == 5 and stats.loss == 0.0
    assert all(r > 0 for r in stats.rtts_ms)


async def test_tcp_closed_port_is_total_loss() -> None:
    stats = await tcp_probe("127.0.0.1", free_port(), **FAST)
    assert stats.sent == 5 and stats.received == 0 and stats.loss == 1.0


async def test_udp_echo_reachable(node: Node) -> None:
    stats = await udp_probe(node.host, node.udp_port, **FAST)
    assert stats.received == 5 and stats.loss == 0.0


async def test_udp_closed_port_is_total_loss() -> None:
    stats = await udp_probe("127.0.0.1", free_port(socket.SOCK_DGRAM), **FAST)
    assert stats.sent == 5 and stats.received == 0 and stats.loss == 1.0


async def test_udp_loss_with_server_dropping_every_other_packet() -> None:
    n, handles = await start_node(drop_every=2)
    try:
        stats = await udp_probe(n.host, n.udp_port, samples=6, timeout=0.2)
    finally:
        await stop_node(handles)
    assert n.udp.count == 6
    assert stats.received == 3
    assert stats.loss == pytest.approx(0.5)


async def test_udp_ignores_mismatched_replies() -> None:
    n, handles = await start_node(junk_first=True)
    try:
        stats = await udp_probe(n.host, n.udp_port, **FAST)
    finally:
        await stop_node(handles)
    assert stats.received == 5 and stats.loss == 0.0


async def test_fetch_load_ok_404_and_unreachable() -> None:
    ok, h1 = await start_node(load=0.42)
    missing, h2 = await start_node(load=None)
    try:
        assert await fetch_load("127.0.0.1", ok.http_port, timeout=0.5) == 0.42
        assert await fetch_load("127.0.0.1", missing.http_port, timeout=0.5) is None
        assert await fetch_load("127.0.0.1", free_port(), timeout=0.5) is None
    finally:
        await stop_node(h1 + h2)


def test_summarize_prefers_udp_then_tcp() -> None:
    udp = SampleStats(sent=5, rtts_ms=[10.0, 12.0])
    tcp = SampleStats(sent=5, rtts_ms=[30.0] * 5)
    r = summarize("s1", udp, tcp, 0.1)
    assert r.reachable and r.rtt_ms_p50 == 11.0 and r.loss == 0.6

    r = summarize("s1", SampleStats(sent=5), tcp, None)
    assert r.reachable and r.rtt_ms_p50 == 30.0 and r.loss == 0.0 and r.load is None

    r = summarize("s1", SampleStats(sent=5), SampleStats(sent=5), None)
    assert not r.reachable and r.rtt_ms_p50 is None and r.rtt_ms_p95 is None and r.loss == 1.0


async def test_probe_server_end_to_end(node: Node) -> None:
    server = Server(
        id="srv-1",
        name="local-01",
        public_ipv4="127.0.0.1",
        wg_port=node.udp_port - 1,
        ss_port=node.tcp_port,
    )
    cfg = ProbeConfig(samples=3, timeout_s=0.3, gap_s=0, load_port=node.http_port)
    r = await probe_server(server, cfg)
    assert r.server_id == "srv-1" and r.reachable and r.loss == 0.0 and r.load == 0.35
    assert r.rtt_ms_p50 is not None and r.rtt_ms_p95 is not None
    assert r.rtt_ms_p50 <= r.rtt_ms_p95


async def test_probe_server_fully_down() -> None:
    udp_closed = free_port(socket.SOCK_DGRAM)
    server = Server(
        id="srv-down",
        name="dead-01",
        public_ipv4="127.0.0.1",
        wg_port=udp_closed - 1,
        ss_port=free_port(),
    )
    cfg = ProbeConfig(samples=2, timeout_s=0.2, gap_s=0, load_port=free_port(), load_timeout_s=0.2)
    r = await probe_server(server, cfg)
    assert r.model_dump() == {
        "server_id": "srv-down",
        "reachable": False,
        "rtt_ms_p50": None,
        "rtt_ms_p95": None,
        "loss": 1.0,
        "load": None,
    }


# ------------------------------------------------------------------ scale & robustness


async def test_paced_samples_bound_the_time_spent_on_a_dead_server() -> None:
    # A bound UDP socket that never answers: every sample times out.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as silent:
        silent.bind(("127.0.0.1", 0))
        t0 = time.monotonic()
        stats = await udp_probe(
            "127.0.0.1", silent.getsockname()[1], samples=5, timeout=0.3, gap=0.05
        )
        elapsed = time.monotonic() - t0
    assert stats.sent == 5 and stats.received == 0
    # Paced: (samples - 1) * gap + timeout = 0.5 s, not samples * timeout = 1.5 s.
    assert 0.45 <= elapsed < 0.9, elapsed


def _thread_udp_echo() -> tuple[socket.socket, threading.Thread]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))

    def run() -> None:
        with contextlib.suppress(OSError):
            while True:
                data, addr = sock.recvfrom(64)
                sock.sendto(data, addr)

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return sock, t


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="kernel timestamps are Linux")
async def test_rtts_are_not_inflated_by_a_busy_event_loop() -> None:
    """Echo/handshake answered by another thread while our loop is blocked for 200 ms."""
    echo, _ = _thread_udp_echo()
    listener = socket.create_server(("127.0.0.1", 0))  # kernel completes handshakes itself
    loop = asyncio.get_running_loop()
    try:
        loop.call_soon(time.sleep, 0.2)  # runs right after the (synchronous) first send
        udp = await udp_probe("127.0.0.1", echo.getsockname()[1], samples=1, timeout=1.0)
        loop.call_soon(time.sleep, 0.2)
        tcp = await tcp_probe("127.0.0.1", listener.getsockname()[1], samples=1, timeout=1.0)
    finally:
        echo.close()
        listener.close()
    assert udp.received == 1 and udp.rtts_ms[0] < 50, udp.rtts_ms
    assert tcp.received == 1 and tcp.rtts_ms[0] < 50, tcp.rtts_ms


async def _serve_raw(response: bytes, keep_open: bool = False) -> tuple[asyncio.Server, int]:
    async def handle(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        while (await r.readline()) not in (b"\r\n", b""):
            pass
        w.write(response)
        await w.drain()
        if keep_open:
            await r.read()  # hold the connection until the client hangs up
        w.close()

    srv = await asyncio.start_server(handle, "127.0.0.1", 0)
    return srv, srv.sockets[0].getsockname()[1]


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (b'HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\n{"load": 0.5}', 0.5),
        (b'HTTP/1.0 200 OK\r\n\r\n{"load": 1}', 1.0),
        (
            b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nd\r\n{"load": 0.5}\r\n0\r\n\r\n',
            None,
        ),
        (b'HTTP/1.1 500 X\r\nContent-Length: 13\r\n\r\n{"load": 0.5}', None),
        (b'HTTP/1.1 200 OK\r\n\r\n{"load": 1.5}', None),
        (b'HTTP/1.1 200 OK\r\n\r\n{"load": true}', None),
        (b"HTTP/1.1 200 OK\r\n\r\n[1]", None),
        (b"HTTP/1.1 200 OK\r\n\r\n" + b" " * 9000 + b'{"load": 0.5}', None),  # over 8 KiB
        (b"garbage", None),
    ],
)
async def test_fetch_load_parsing(response: bytes, expected: float | None) -> None:
    srv, port = await _serve_raw(response)
    async with srv:
        assert await fetch_load("127.0.0.1", port, timeout=0.5) == expected


async def test_fetch_load_does_not_wait_for_close_when_content_length_is_complete() -> None:
    body = b'HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\n{"load": 0.2}'
    srv, port = await _serve_raw(body, keep_open=True)
    async with srv:
        t0 = time.monotonic()
        assert await fetch_load("127.0.0.1", port, timeout=2.0) == 0.2
        assert time.monotonic() - t0 < 1.0


def test_worst_case_and_fd_budget() -> None:
    cfg = ProbeConfig(samples=5, timeout_s=1.0, gap_s=0.05, load_timeout_s=1.0)
    assert cfg.worst_case_s == pytest.approx(1.2)
    assert fds_per_server(5) == 7
