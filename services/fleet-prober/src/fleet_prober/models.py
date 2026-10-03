"""Wire models for the internal api (docs/CONTRACT.md, "Internal API")."""

from __future__ import annotations

from datetime import UTC, datetime
from ipaddress import IPv4Address

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, field_serializer


class Server(BaseModel):
    """One entry of `GET /internal/v1/servers`. Unknown fields are ignored."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    id: str
    name: str
    public_ipv4: IPv4Address
    wg_port: int = Field(ge=1, le=65534)  # wg_port + 1 must be a valid port
    ss_port: int = Field(ge=1, le=65535)

    @property
    def echo_port(self) -> int:
        """UDP echo health port that sits beside WireGuard (node-agent contract)."""
        return self.wg_port + 1


ServerList = TypeAdapter(list[Server])


class ServerResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    server_id: str
    reachable: bool
    rtt_ms_p50: float | None
    rtt_ms_p95: float | None
    loss: float = Field(ge=0.0, le=1.0)
    load: float | None = Field(ge=0.0, le=1.0)


class HeartbeatBatch(BaseModel):
    """Body of `POST /internal/v1/servers/heartbeats`."""

    model_config = ConfigDict(extra="forbid")

    prober_id: str
    observed_at: datetime
    results: list[ServerResult]

    @field_serializer("observed_at")
    def _rfc3339_utc(self, value: datetime) -> str:
        # Contract: RFC 3339 UTC, e.g. "2026-10-02T12:00:00Z".
        return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
