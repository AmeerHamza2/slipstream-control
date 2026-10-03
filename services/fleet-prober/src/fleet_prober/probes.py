"""Network probes: TCP connect RTT, UDP echo RTT/loss, and node load.

All probes are failure-tolerant: network errors become lost samples, never exceptions.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import math
import os
import platform
import socket
import struct
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass, field

from fleet_prober import metrics
from fleet_prober.models import Server, ServerResult

NONCE_BYTES = 16


@dataclass(slots=True)
class SampleStats:
    """Outcome of N probe samples against one endpoint."""

    sent: int = 0
    rtts_ms: list[float] = field(default_factory=list)

    @property
    def received(self) -> int:
        return len(self.rtts_ms)

    @property
    def loss(self) -> float:
        return 1.0 - self.received / self.sent if self.sent else 1.0

    def percentile(self, q: float) -> float | None:
        return percentile(self.rtts_ms, q)


def percentile(values: Sequence[float], q: float) -> float | None:
    """Linear-interpolated percentile (same as numpy's default); None for no data."""
    if not values:
        return None
    if not 0.0 <= q <= 100.0:
        raise ValueError("q must be within [0, 100]")
    ordered = sorted(values)
    rank = (len(ordered) - 1) * q / 100.0
    lo, hi = math.floor(rank), math.ceil(rank)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (rank - lo)


def _record(kind: str, outcome: str, rtt_ms: float | None = None) -> None:
    metrics.PROBE_SAMPLES.labels(kind=kind, outcome=outcome).inc()
    if rtt_ms is not None:
        metrics.PROBE_RTT.labels(kind=kind).observe(rtt_ms / 1000.0)


# ------------------------------------------------------------------ timestamps
#
# With hundreds of probes on one event loop, "now" in a callback is late by however long
# the loop took to get there, which inflates every RTT (measured: +28 ms median at 256
# concurrent servers with loop-side timestamps). So on Linux the kernel's own numbers are
# used: SO_TIMESTAMPNS receive timestamps for UDP echoes, and the handshake RTT the TCP
# stack measured (TCP_INFO.tcpi_rtt) for connects. Elsewhere, loop timestamps are used.

_LINUX = sys.platform == "linux" and platform.machine() in {"x86_64", "aarch64", "arm64"}
SO_TIMESTAMPNS = 35  # asm-generic/socket.h (SO_TIMESTAMPNS_OLD; same value as SCM_*)
_TIMESPEC = struct.Struct("@qq")
_TCPI_RTT_OFFSET = 68  # struct tcp_info: 8 x u8, then u32 fields; tcpi_rtt is the 16th (us)


def _tcp_kernel_rtt_ms(sock: socket.socket | None) -> float | None:
    if sock is None or not _LINUX:
        return None
    try:
        info = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 104)
    except OSError:
        return None
    if len(info) < _TCPI_RTT_OFFSET + 4:
        return None
    rtt_us = int.from_bytes(info[_TCPI_RTT_OFFSET : _TCPI_RTT_OFFSET + 4], sys.byteorder)
    return rtt_us / 1000.0 if rtt_us > 0 else None


# --------------------------------------------------------------------------- TCP
#
# Samples are *paced*, not sequential: sample i starts at i * gap and each has its own
# timeout. A live node costs about (samples - 1) * gap + RTT, and a blackholed one
# (samples - 1) * gap + timeout, instead of samples * timeout. At fleet scale (1,000+
# servers, some of them always down) this is what keeps a cycle inside the interval.
# Cost: up to `samples` sockets per server at once (see fds_per_server).


class _Discard(asyncio.Protocol):
    """Bare protocol: we only time the handshake (no StreamReader/Writer overhead)."""


async def _tcp_sample(host: str, port: int, delay: float, timeout: float) -> float | str:
    if delay:
        await asyncio.sleep(delay)
    loop = asyncio.get_running_loop()
    start = time.perf_counter()
    try:
        transport, _ = await asyncio.wait_for(loop.create_connection(_Discard, host, port), timeout)
    except TimeoutError:
        return "timeout"
    except OSError:
        return "error"
    loop_rtt_ms = (time.perf_counter() - start) * 1000.0
    kernel_rtt_ms = _tcp_kernel_rtt_ms(transport.get_extra_info("socket"))
    transport.close()
    # The kernel's SYN -> SYN-ACK time excludes event-loop delay; it can only be shorter.
    return min(loop_rtt_ms, kernel_rtt_ms) if kernel_rtt_ms is not None else loop_rtt_ms


async def tcp_probe(
    host: str, port: int, *, samples: int, timeout: float, gap: float = 0.0
) -> SampleStats:
    """Time `samples` TCP handshakes, paced `gap` apart. Refused/timeout is a lost sample."""
    stats = SampleStats()
    outcomes = await asyncio.gather(
        *(_tcp_sample(host, port, i * gap, timeout) for i in range(samples))
    )
    stats.sent = samples
    for o in outcomes:
        if isinstance(o, str):
            _record("tcp", o)
        else:
            stats.rtts_ms.append(o)
            _record("tcp", "ok", o)
    return stats


# --------------------------------------------------------------------------- UDP


class _UdpEcho:
    """A connected, non-blocking UDP socket read straight from the selector.

    Echoes are matched to outstanding nonces; anything else (late, duplicated, spoofed)
    is ignored. Receive times come from the kernel (SO_TIMESTAMPNS) when available.
    """

    def __init__(self, loop: asyncio.AbstractEventLoop, host: str, port: int) -> None:
        self.loop = loop
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.pending: dict[bytes, asyncio.Future[int]] = {}
        self.failed: OSError | None = None
        self.kernel_ts = False
        try:
            self.sock.setblocking(False)
            if _LINUX:
                with contextlib.suppress(OSError):
                    self.sock.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
                    self.kernel_ts = True
            self.sock.connect((host, port))  # UDP connect: no packets, enables ICMP errors
            loop.add_reader(self.sock.fileno(), self._readable)
        except BaseException:
            self.sock.close()
            raise

    def send(self, nonce: bytes) -> tuple[int, asyncio.Future[int]] | None:
        """Send one nonce; returns (send time ns, future of receive time ns)."""
        fut: asyncio.Future[int] = self.loop.create_future()
        self.pending[nonce] = fut
        sent_at = time.time_ns()
        try:
            self.sock.send(nonce)
        except OSError as exc:  # ICMP error already queued, or no buffer space
            self.pending.pop(nonce, None)
            self._fail(exc)
            return None
        return sent_at, fut

    def _readable(self) -> None:
        while True:
            try:
                data, ancdata, _flags, _addr = self.sock.recvmsg(64, 64)
            except (BlockingIOError, InterruptedError):
                return
            except OSError as exc:  # ICMP port/host unreachable on the connected socket
                self._fail(exc)
                return
            received_at = time.time_ns()
            for level, kind, payload in ancdata:
                if level == socket.SOL_SOCKET and kind == SO_TIMESTAMPNS:
                    if len(payload) >= _TIMESPEC.size:
                        sec, nsec = _TIMESPEC.unpack_from(payload)
                        received_at = sec * 1_000_000_000 + nsec
            fut = self.pending.pop(data, None)
            if fut is not None and not fut.done():
                fut.set_result(received_at)

    def _fail(self, exc: OSError) -> None:
        # Fail outstanding samples fast instead of waiting for the timeout; stop sending.
        self.failed = exc
        for fut in self.pending.values():
            if not fut.done():
                fut.set_exception(exc)
        self.pending.clear()

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self.loop.remove_reader(self.sock.fileno())
        self.sock.close()
        self.pending.clear()


async def udp_probe(
    host: str, port: int, *, samples: int, timeout: float, gap: float = 0.0
) -> SampleStats:
    """Send `samples` random 16-byte nonces, paced `gap` apart, and time the echoes.

    Each sample has its own `timeout` measured from its send; a later echo is a loss.
    Replies that don't match an outstanding nonce (late, duplicated, spoofed) are ignored.
    """
    stats = SampleStats(sent=samples)
    loop = asyncio.get_running_loop()
    try:
        echo = _UdpEcho(loop, host, port)
    except OSError:
        for _ in range(samples):
            _record("udp", "error")
        return stats
    sent: list[tuple[int, asyncio.Future[int]]] = []
    try:
        for i in range(samples):
            if i and gap:
                await asyncio.sleep(gap)
            if echo.failed is not None:
                break
            s = echo.send(os.urandom(NONCE_BYTES))
            if s is None:
                break
            sent.append(s)
        if sent:
            # Wait until every sample has either answered or used up its own timeout.
            remaining = sent[-1][0] / 1e9 + timeout - time.time()
            pending = [f for _, f in sent if not f.done()]
            if pending and remaining > 0:
                await asyncio.wait(pending, timeout=remaining)
    finally:
        echo.close()
        for _, f in sent:
            if not f.done():
                f.cancel()

    timeout_ns = timeout * 1e9
    for sent_at, f in sent:
        if f.cancelled():
            _record("udp", "timeout")
        elif f.exception() is not None:
            _record("udp", "error")
        else:
            rtt_ns = max(0, f.result() - sent_at)
            if rtt_ns > timeout_ns:
                _record("udp", "timeout")  # answered, but later than its own deadline
                continue
            stats.rtts_ms.append(rtt_ns / 1e6)
            _record("udp", "ok", rtt_ns / 1e6)
    for _ in range(samples - len(sent)):  # never sent: the socket already reported an error
        _record("udp", "error")
    return stats


# -------------------------------------------------------------------------- load

MAX_LOAD_RESPONSE = 8 * 1024


async def fetch_load(host: str, port: int, *, timeout: float, path: str = "/load") -> float | None:
    """GET the node's `{"load": 0.35}` endpoint. Any failure or bad value means None.

    A deliberately tiny HTTP/1.1 client (Connection: close, 8 KiB cap, one deadline for
    connect + request + response). At ~2,000 nodes per cycle a general-purpose client's
    per-request CPU is significant and, on a single event loop, inflates the RTTs the
    other probes measure; this costs about a tenth.
    """
    writer: asyncio.StreamWriter | None = None
    try:
        async with asyncio.timeout(timeout):
            reader, writer = await asyncio.open_connection(host, port, limit=MAX_LOAD_RESPONSE)
            writer.write(
                f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nAccept: application/json\r\n"
                "Connection: close\r\nUser-Agent: fleet-prober\r\n\r\n".encode()
            )
            data = b""
            # Read until EOF, the cap, or a complete Content-Length body (in case the
            # node keeps the connection open despite `Connection: close`).
            while len(data) <= MAX_LOAD_RESPONSE and not _complete(data):
                chunk = await reader.read(MAX_LOAD_RESPONSE + 1 - len(data))
                if not chunk:
                    break
                data += chunk
    except (OSError, TimeoutError, ValueError):
        return None
    finally:
        if writer is not None:
            writer.close()
    return _parse_load_response(data)


def _complete(data: bytes) -> bool:
    head, sep, body = data.partition(b"\r\n\r\n")
    if not sep:
        return False
    for line in head.split(b"\r\n")[1:]:
        k, _, v = line.partition(b":")
        if k.strip().lower() == b"content-length" and v.strip().isdigit():
            return len(body) >= int(v.strip())
    return False


def _parse_load_response(data: bytes) -> float | None:
    if len(data) > MAX_LOAD_RESPONSE:
        return None
    head, sep, body = data.partition(b"\r\n\r\n")
    if not sep:
        return None
    lines = head.split(b"\r\n")
    parts = lines[0].split(b" ", 2)
    if len(parts) < 2 or not parts[0].startswith(b"HTTP/1.") or parts[1] != b"200":
        return None
    headers = {}
    for line in lines[1:]:
        k, _, v = line.partition(b":")
        headers[k.strip().lower()] = v.strip().lower()
    if headers.get(b"transfer-encoding", b"identity") != b"identity":
        return None  # chunked & co: not part of the node-agent contract
    if (cl := headers.get(b"content-length")) is not None:
        if not cl.isdigit() or int(cl) > len(body):
            return None
        body = body[: int(cl)]
    try:
        doc = json.loads(body)
    except ValueError:
        return None
    value = doc.get("load") if isinstance(doc, dict) else None
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    value = float(value)
    return value if 0.0 <= value <= 1.0 else None


# ------------------------------------------------------------------- per server


# Worst-case sockets one server's probe holds at once: 1 UDP + `samples` TCP + 1 HTTP.
def fds_per_server(samples: int) -> int:
    return samples + 2


@dataclass(frozen=True, slots=True)
class ProbeConfig:
    samples: int = 5
    timeout_s: float = 1.0
    gap_s: float = 0.05
    load_port: int = 9100
    load_timeout_s: float = 1.0

    @property
    def worst_case_s(self) -> float:
        """Longest a single server's probe can take (all samples timing out)."""
        return max((self.samples - 1) * self.gap_s + self.timeout_s, self.load_timeout_s)


def summarize(
    server_id: str, udp: SampleStats, tcp: SampleStats, load: float | None
) -> ServerResult:
    """Combine probe outcomes per the contract.

    reachable if either probe got a reply; rtt/loss from UDP when it got replies,
    otherwise TCP; unreachable servers report null RTTs and loss 1.0.
    """
    best = udp if udp.received else tcp if tcp.received else None
    if best is None:
        return ServerResult(
            server_id=server_id,
            reachable=False,
            rtt_ms_p50=None,
            rtt_ms_p95=None,
            loss=1.0,
            load=load,
        )
    p50, p95 = best.percentile(50), best.percentile(95)
    return ServerResult(
        server_id=server_id,
        reachable=True,
        rtt_ms_p50=round(p50, 2) if p50 is not None else None,
        rtt_ms_p95=round(p95, 2) if p95 is not None else None,
        loss=round(best.loss, 4),
        load=load,
    )


async def probe_server(server: Server, cfg: ProbeConfig) -> ServerResult:
    host = str(server.public_ipv4)
    udp, tcp, load = await asyncio.gather(
        udp_probe(
            host, server.echo_port, samples=cfg.samples, timeout=cfg.timeout_s, gap=cfg.gap_s
        ),
        tcp_probe(host, server.ss_port, samples=cfg.samples, timeout=cfg.timeout_s, gap=cfg.gap_s),
        fetch_load(host, cfg.load_port, timeout=cfg.load_timeout_s),
    )
    return summarize(server.id, udp, tcp, load)
