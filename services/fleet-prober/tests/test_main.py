"""CLI wiring: fd budget, shard config validation, container healthcheck."""

from __future__ import annotations

import io
import resource
import time
from typing import Any

import pytest
from pydantic import ValidationError

from fleet_prober import __main__ as cli
from fleet_prober.config import Settings


def test_concurrency_is_capped_by_the_open_file_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(resource, "getrlimit", lambda _r: (400, 400))
    monkeypatch.setattr(resource, "setrlimit", lambda *_a: None)
    s = Settings(probe_concurrency=256, probe_samples=5)
    assert cli.effective_concurrency(s) == (400 - cli.FD_RESERVE) // 7
    assert cli.effective_concurrency(Settings(probe_concurrency=8)) == 8


def test_soft_limit_is_raised_to_the_hard_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[int, int]] = []
    monkeypatch.setattr(resource, "getrlimit", lambda _r: (1024, 65536))
    monkeypatch.setattr(resource, "setrlimit", lambda _r, v: calls.append(v))
    assert cli.raise_nofile_limit() == 65536
    assert calls == [(65536, 65536)]


@pytest.mark.parametrize("spec", ["2/2", "0/0", "a/b", "1"])
def test_bad_shard_is_a_config_error(spec: str) -> None:
    with pytest.raises(ValidationError):
        Settings(prober_shard=spec)


def _metrics(text: str) -> Any:
    class Resp(io.BytesIO):
        def __enter__(self) -> Resp:
            return self

        def __exit__(self, *_a: object) -> None:
            pass

    return lambda *_a, **_k: Resp(text.encode())


def test_healthcheck(monkeypatch: pytest.MonkeyPatch) -> None:
    s = Settings(probe_interval_s=15, metrics_port=9101)
    now = time.time()
    fresh = f"fleet_prober_last_cycle_timestamp_seconds {now - 10}\n"
    stale = f"fleet_prober_last_cycle_timestamp_seconds {now - 600}\n"
    starting = f"fleet_prober_last_cycle_timestamp_seconds 0.0\nprocess_start_time_seconds {now}\n"
    for text, want in ((fresh, 0), (stale, 1), (starting, 0), ("nothing here\n", 1)):
        monkeypatch.setattr(cli.urllib.request, "urlopen", _metrics(text))
        assert cli.healthcheck(s) == want, text

    def down(*_a: object, **_k: object) -> None:
        raise OSError("refused")

    monkeypatch.setattr(cli.urllib.request, "urlopen", down)
    assert cli.healthcheck(s) == 1
