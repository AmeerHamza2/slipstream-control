"""Local VPN-node simulator for demos and tests (stdlib only).

Exposes what fleet-prober expects from a node:
  * TCP listener on the Shadowsocks port (accepts and closes),
  * UDP echo on wg_port + 1 (optionally dropping a fraction of packets, or adding delay),
  * HTTP `GET /load` -> {"load": <float>} on the load port.

    python tools/fake_node.py --host 127.0.0.2 --wg-port 51820 --ss-port 8443 --load 0.35
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random


class UdpEcho(asyncio.DatagramProtocol):
    def __init__(self, drop: float = 0.0, delay_ms: float = 0.0) -> None:
        self.drop = drop
        self.delay_s = delay_ms / 1000.0
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.DatagramTransport)
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str | int, ...]) -> None:
        if self.transport is None or random.random() < self.drop:
            return
        if self.delay_s:
            asyncio.get_running_loop().call_later(self.delay_s, self.transport.sendto, data, addr)
        else:
            self.transport.sendto(data, addr)


async def _tcp_accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    writer.close()


def _http_handler(load: float | None):  # type: ignore[no-untyped-def]
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request_line = await reader.readline()
            while (await reader.readline()) not in (b"\r\n", b"\n", b""):
                pass
            parts = request_line.decode(errors="replace").split()
            if len(parts) >= 2 and parts[0] == "GET" and parts[1] == "/load" and load is not None:
                status, body = "200 OK", json.dumps({"load": load}).encode()
            else:
                status, body = "404 Not Found", b'{"error":"not_found"}'
            writer.write(
                f"HTTP/1.1 {status}\r\nContent-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                + body
            )
            await writer.drain()
        finally:
            writer.close()

    return handle


async def run(args: argparse.Namespace) -> None:
    loop = asyncio.get_running_loop()
    udp, _ = await loop.create_datagram_endpoint(
        lambda: UdpEcho(args.drop, args.delay_ms), local_addr=(args.host, args.wg_port + 1)
    )
    tcp = await asyncio.start_server(_tcp_accept, args.host, args.ss_port)
    http = await asyncio.start_server(_http_handler(args.load), args.host, args.load_port)
    print(
        f"fake node on {args.host}: udp-echo :{args.wg_port + 1}  tcp :{args.ss_port}  "
        f"http :{args.load_port}/load  (load={args.load}, drop={args.drop})",
        flush=True,
    )
    try:
        async with tcp, http:
            await asyncio.gather(tcp.serve_forever(), http.serve_forever())
    finally:
        udp.close()


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--wg-port", type=int, default=51820, help="UDP echo listens on this + 1")
    p.add_argument("--ss-port", type=int, default=8443)
    p.add_argument("--load-port", type=int, default=9100)
    p.add_argument("--load", type=float, default=0.35, help="value served by /load")
    p.add_argument(
        "--no-load", dest="load", action="store_const", const=None, help="serve 404 on /load"
    )
    p.add_argument("--drop", type=float, default=0.0, help="UDP drop probability 0..1")
    p.add_argument("--delay-ms", type=float, default=0.0, help="added UDP echo delay")
    try:
        asyncio.run(run(p.parse_args()))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
