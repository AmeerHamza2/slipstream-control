"""Fleet simulator for scale tests (stdlib only): many fake nodes plus a fake api.

One process hosts N live nodes on loopback addresses 127.1.x.y (UDP echo on wg_port + 1
with a per-node delay, TCP listener on ss_port, HTTP /load) and a fake api on
127.0.0.1:<api-port> that serves the fleet (live nodes plus D blackholed ones on
198.51.100.0/24, TEST-NET-2, which time out) and verifies every heartbeat POST (HMAC,
1 MiB body limit, <= 5,000 results, as the Go api does). Stats: GET /stats.

    python tools/fleet_sim.py --nodes 1000 --dead 100 --api-port 18099 --secret s3cret

Needs about 3 file descriptors per live node (ulimit -n).
"""

from __future__ import annotations

import argparse
import asyncio
import functools
import hashlib
import hmac
import json
import random
import time
import uuid
from typing import Any

MAX_BODY = 1 << 20
MAX_RESULTS = 5000


class UdpEcho(asyncio.DatagramProtocol):
    def __init__(self, delay_s: float, drop: float) -> None:
        self.delay_s = delay_s
        self.drop = drop
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.DatagramTransport)
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str | int, ...]) -> None:
        if self.transport is None or random.random() < self.drop:
            return
        delay = self.delay_s * random.uniform(0.9, 1.1)
        asyncio.get_running_loop().call_later(delay, self.transport.sendto, data, addr)


async def _tcp_accept(_r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
    w.close()


def _load_handler(load: float) -> Any:
    body = json.dumps({"load": load}).encode()

    async def handle(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        try:
            while (await r.readline()) not in (b"\r\n", b"\n", b""):
                pass
            w.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                + body
            )
            await w.drain()
        except OSError:
            pass
        finally:
            w.close()

    return handle


class FakeApi:
    def __init__(self, secret: bytes, servers: list[dict[str, Any]]) -> None:
        self.secret = secret
        self.servers = servers
        self.server_json = json.dumps(servers).encode()
        self.posts: list[dict[str, Any]] = []
        self.results_by_server: dict[str, int] = {}
        self.rejected: list[str] = []
        self.fail_next = 0

    def _verify(self, method: str, path: str, headers: dict[str, str], body: bytes) -> bool:
        try:
            ts = int(headers["x-slipstream-timestamp"])
            sig = headers["x-slipstream-signature"]
        except (KeyError, ValueError):
            return False
        if abs(time.time() - ts) > 300 or headers.get("x-slipstream-service") != "fleet-prober":
            return False
        msg = f"{ts}.{method}.{path}.".encode() + body
        want = "v1=" + hmac.new(self.secret, msg, hashlib.sha256).hexdigest()
        return hmac.compare_digest(want, sig)

    async def handle(self, r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        try:
            while True:
                line = await r.readline()
                if not line:
                    return
                method, target, _ = line.decode().split(" ", 2)
                headers: dict[str, str] = {}
                while (h := await r.readline()) not in (b"\r\n", b"\n", b""):
                    k, _, v = h.decode().partition(":")
                    headers[k.strip().lower()] = v.strip()
                length = int(headers.get("content-length", "0"))
                if length > MAX_BODY:
                    await self._send(w, 413, b'{"error":{"code":"invalid_request"}}')
                    self.rejected.append(f"body {length} > 1MiB")
                    return
                body = await r.readexactly(length) if length else b""
                path = target.split("?", 1)[0]
                status, out = self.route(method, path, headers, body)
                await self._send(w, status, out)
        except (OSError, ValueError, asyncio.IncompleteReadError):
            return
        finally:
            w.close()

    def route(
        self, method: str, path: str, headers: dict[str, str], body: bytes
    ) -> tuple[int, bytes]:
        if method == "GET" and path == "/stats":
            sizes = [p["bytes"] for p in self.posts]
            counts = [p["results"] for p in self.posts]
            stats = {
                "posts": len(self.posts),
                "max_body_bytes": max(sizes, default=0),
                "max_results_per_post": max(counts, default=0),
                "results_total": sum(counts),
                "distinct_servers_reported": len(self.results_by_server),
                "rejected": self.rejected[-10:],
                "probers": sorted({p["prober_id"] for p in self.posts}),
            }
            return 200, json.dumps(stats).encode()
        if method == "POST" and path == "/fail":
            self.fail_next = int(body or b"1")
            return 200, b"{}"
        if not self._verify(method, path, headers, body):
            self.rejected.append(f"bad signature {method} {path}")
            return 401, b'{"error":{"code":"unauthorized"}}'
        if method == "GET" and path == "/internal/v1/servers":
            return 200, self.server_json
        if method == "POST" and path == "/internal/v1/servers/heartbeats":
            if self.fail_next > 0:
                self.fail_next -= 1
                return 503, b'{"error":{"code":"internal"}}'
            batch = json.loads(body)
            results = batch["results"]
            if len(results) > MAX_RESULTS:
                self.rejected.append(f"{len(results)} results > {MAX_RESULTS}")
                return 400, b'{"error":{"code":"invalid_request"}}'
            self.posts.append(
                {"bytes": len(body), "results": len(results), "prober_id": batch["prober_id"]}
            )
            for res in results:
                sid = res["server_id"]
                self.results_by_server[sid] = self.results_by_server.get(sid, 0) + 1
            return 202, json.dumps({"accepted": len(results)}).encode()
        return 404, b'{"error":{"code":"not_found"}}'

    @staticmethod
    async def _send(w: asyncio.StreamWriter, status: int, body: bytes) -> None:
        w.write(
            f"HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n\r\n".encode()
            + body
        )
        await w.drain()


def _addr(i: int) -> str:
    return f"127.1.{i // 250}.{i % 250 + 1}"


async def run(args: argparse.Namespace) -> None:
    loop = asyncio.get_running_loop()
    rng = random.Random(args.seed)
    servers: list[dict[str, Any]] = []
    closers: list[Any] = []
    for i in range(args.nodes):
        host = _addr(i)
        delay = rng.uniform(args.min_delay_ms, args.max_delay_ms) / 1000.0
        udp, _ = await loop.create_datagram_endpoint(
            functools.partial(UdpEcho, delay, args.drop), local_addr=(host, args.wg_port + 1)
        )
        tcp = await asyncio.start_server(_tcp_accept, host, args.ss_port, backlog=64)
        http = await asyncio.start_server(
            _load_handler(round(rng.random(), 2)), host, args.load_port, backlog=64
        )
        closers += [udp, tcp, http]
        servers.append(
            {
                "id": str(uuid.UUID(int=rng.getrandbits(128), version=4)),
                "name": f"sim-{i:04d}",
                "public_ipv4": host,
                "wg_port": args.wg_port,
                "ss_port": args.ss_port,
                "sim_delay_ms": round(delay * 1000, 2),  # extra field: ignored by the prober
            }
        )
    for i in range(args.dead):
        servers.append(
            {
                "id": str(uuid.UUID(int=rng.getrandbits(128), version=4)),
                "name": f"dead-{i:04d}",
                "public_ipv4": f"198.51.100.{i % 254 + 1}",
                "wg_port": 40000 + 2 * (i // 254),
                "ss_port": 30000 + i // 254,
            }
        )
    rng.shuffle(servers)
    api = FakeApi(args.secret.encode(), servers)
    api_server = await asyncio.start_server(api.handle, "127.0.0.1", args.api_port, backlog=128)
    print(
        json.dumps({"ready": True, "live": args.nodes, "dead": args.dead, "api": args.api_port}),
        flush=True,
    )
    async with api_server:
        await api_server.serve_forever()


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--nodes", type=int, default=1000)
    p.add_argument("--dead", type=int, default=100, help="blackholed servers (timeouts)")
    p.add_argument("--api-port", type=int, default=18099)
    p.add_argument("--secret", default="sim-prober-secret")
    p.add_argument("--wg-port", type=int, default=51820)
    p.add_argument("--ss-port", type=int, default=8443)
    p.add_argument("--load-port", type=int, default=9100)
    p.add_argument("--min-delay-ms", type=float, default=5.0)
    p.add_argument("--max-delay-ms", type=float, default=150.0)
    p.add_argument("--drop", type=float, default=0.02, help="UDP drop probability")
    p.add_argument("--seed", type=int, default=7)
    try:
        asyncio.run(run(p.parse_args()))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
