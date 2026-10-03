"""Runtime configuration, loaded from environment variables (see docs/CONTRACT.md)."""

from __future__ import annotations

from pathlib import Path

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="", case_sensitive=False, extra="ignore")

    # Contract-defined settings.
    api_url: str = Field(default="http://localhost:8080", description="Base URL of the api")
    prober_id: str = Field(default="prober-local", min_length=1)
    prober_service_secret: SecretStr = Field(default=SecretStr(""))
    probe_interval_s: float = Field(default=15.0, gt=0)
    # 256 covers ~2,000 servers in a few seconds with the paced probes (see README,
    # "Scale & robustness"); the effective value is capped by the open-file limit.
    probe_concurrency: int = Field(default=256, ge=1, le=4096)
    probe_timeout_s: float = Field(default=1.0, gt=0, description="Per-sample timeout")

    # Operational knobs (not part of the cross-service contract).
    probe_samples: int = Field(default=5, ge=1)
    probe_sample_gap_s: float = Field(default=0.05, ge=0, description="Pause between samples")
    load_port: int = Field(default=9100, ge=1, le=65535)
    load_timeout_s: float = Field(default=1.0, gt=0)
    interval_jitter: float = Field(default=0.1, ge=0, le=0.5, description="+/- fraction")
    metrics_port: int = Field(default=9101, ge=0, le=65535, description="0 disables")
    http_timeout_s: float = Field(default=5.0, gt=0)
    retry_attempts: int = Field(default=5, ge=1)
    retry_base_s: float = Field(default=0.5, ge=0)
    retry_max_s: float = Field(default=8.0, ge=0)
    # Horizontal split: "i/N" -> probe only servers whose id hashes to i mod N.
    prober_shard: str = Field(default="0/1", pattern=r"^\d+/\d+$")
    heartbeat_batch_size: int = Field(default=500, ge=1, le=5000)
    log_level: str = "INFO"
    # Offline demo: read the server list from a JSON file instead of the api.
    servers_file: Path | None = None

    @field_validator("prober_shard")
    @classmethod
    def _valid_shard(cls, v: str) -> str:
        i, n = (int(x) for x in v.split("/"))
        if n < 1 or not 0 <= i < n:
            raise ValueError("PROBER_SHARD must be i/N with 0 <= i < N")
        return v
