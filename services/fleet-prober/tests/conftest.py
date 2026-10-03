from __future__ import annotations

import asyncio
import json
import socket
from collections.abc import AsyncIterator
from dataclasses import dataclass

import pytest


class EchoProtocol(asyncio.DatagramProtocol):
    """UDP echo that can drop every Nth packet and inject junk datagrams."""

    def __init__(self, drop_every: int = 0, junk_first: bool = False) -> None:
        self.drop_every = drop_every
        self.junk_first = junk_first
        self.count = 0
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.DatagramTransport)
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str | int, ...]) -> None:
        assert self.transport is not None
        self.count += 1
        if self.drop_every and self.count % self.drop_every == 0:
            return
        if self.junk_first:
            self.transport.sendto(b"x" * 16, addr)  # mismatched reply, must be ignored
        self.transport.sendto(data, addr)


@dataclass
class Node:
    host: str
    udp_port: int
    tcp_port: int
    http_port: int
    udp: EchoProtocol


def free_port(kind: int = socket.SOCK_STREAM) -> int:
    """A port that is (very likely) closed: bind, read the port, release it."""
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


async def start_node(
    *, drop_every: int = 0, junk_first: bool = False, load: float | None = 0.35
) -> tuple[Node, list[object]]:
    loop = asyncio.get_running_loop()
    transport, proto = await loop.create_datagram_endpoint(
        lambda: EchoProtocol(drop_every, junk_first), local_addr=("127.0.0.1", 0)
    )

    async def on_tcp(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        w.close()

    async def on_http(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        line = await r.readline()
        while (await r.readline()) not in (b"\r\n", b""):
            pass
        if line.startswith(b"GET /load ") and load is not None:
            status, body = "200 OK", json.dumps({"load": load}).encode()
        else:
            status, body = "404 Not Found", b"{}"
        w.write(
            f"HTTP/1.1 {status}\r\nContent-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n".encode()
            + body
        )
        await w.drain()
        w.close()

    tcp = await asyncio.start_server(on_tcp, "127.0.0.1", 0)
    http = await asyncio.start_server(on_http, "127.0.0.1", 0)
    node = Node(
        host="127.0.0.1",
        udp_port=transport.get_extra_info("sockname")[1],
        tcp_port=tcp.sockets[0].getsockname()[1],
        http_port=http.sockets[0].getsockname()[1],
        udp=proto,
    )
    return node, [transport, tcp, http]


async def stop_node(handles: list[object]) -> None:
    for h in handles:
        h.close()  # type: ignore[attr-defined]
        if isinstance(h, asyncio.Server):
            await h.wait_closed()


@pytest.fixture
async def node() -> AsyncIterator[Node]:
    n, handles = await start_node()
    yield n
    await stop_node(handles)
