"""Signed client for the api's internal endpoints, with retry/backoff."""

from __future__ import annotations

import asyncio
import logging
import random
import time
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

from fleet_prober import metrics, signing
from fleet_prober.models import HeartbeatBatch, Server, ServerList

log = logging.getLogger(__name__)

SERVERS_PATH = "/internal/v1/servers"
HEARTBEATS_PATH = "/internal/v1/servers/heartbeats"

Sleep = Callable[[float], Awaitable[None]]


class ApiError(Exception):
    """Non-retryable api response (4xx) or retries exhausted."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


def backoff_delay(attempt: int, base: float, cap: float, rng: random.Random | None = None) -> float:
    """Exponential backoff with full jitter: uniform(0, min(cap, base * 2**attempt))."""
    r = rng or random
    return r.uniform(0.0, min(cap, base * (2**attempt)))


class ApiClient:
    def __init__(
        self,
        http: httpx.AsyncClient,
        secret: bytes,
        *,
        attempts: int = 5,
        backoff_base_s: float = 0.5,
        backoff_max_s: float = 8.0,
        sleep: Sleep = asyncio.sleep,
    ) -> None:
        self._http = http
        self._secret = secret
        self._attempts = attempts
        self._base = backoff_base_s
        self._cap = backoff_max_s
        self._sleep = sleep

    async def get_servers(self) -> list[Server]:
        resp = await self._request("GET", SERVERS_PATH, endpoint="servers")
        return ServerList.validate_json(resp.content)

    async def post_heartbeats(
        self, batch: HeartbeatBatch, *, deadline: float | None = None
    ) -> dict[str, Any]:
        """POST one batch. `deadline` (time.monotonic()) stops retries that would end later."""
        body = batch.model_dump_json().encode()
        resp = await self._request(
            "POST", HEARTBEATS_PATH, body=body, endpoint="heartbeats", deadline=deadline
        )
        result: dict[str, Any] = resp.json()
        return result

    async def _request(
        self,
        method: str,
        path: str,
        *,
        body: bytes = b"",
        endpoint: str,
        deadline: float | None = None,
    ) -> httpx.Response:
        # One request id for every attempt so the api's logs tie the retries together.
        request_id = str(uuid.uuid4())
        last_error = "no attempt made"
        for attempt in range(self._attempts):
            if attempt:
                delay = backoff_delay(attempt - 1, self._base, self._cap)
                if deadline is not None and time.monotonic() + delay >= deadline:
                    raise ApiError(
                        f"{method} {path} gave up after {attempt} attempts at the cycle "
                        f"deadline ({last_error})"
                    )
                log.warning(
                    "api request retry",
                    extra={
                        "endpoint": endpoint,
                        "attempt": attempt + 1,
                        "delay_s": round(delay, 3),
                        "reason": last_error,
                        "request_id": request_id,
                    },
                )
                await self._sleep(delay)
            request = self._http.build_request(method, path, content=body or None)
            # Sign the final URL path (honours any prefix in API_URL), and re-sign on every
            # attempt so the timestamp stays inside the api's 300 s window.
            request.headers.update(signing.sign(self._secret, method, request.url.path, body))
            request.headers["X-Request-Id"] = request_id
            if body:
                request.headers["Content-Type"] = "application/json"
            try:
                resp = await self._http.send(request)
            except httpx.TransportError as exc:  # connect/read errors and timeouts
                metrics.API_REQUESTS.labels(endpoint=endpoint, outcome="network").inc()
                last_error = type(exc).__name__
                continue
            klass = f"{resp.status_code // 100}xx"
            metrics.API_REQUESTS.labels(endpoint=endpoint, outcome=klass).inc()
            if resp.status_code >= 500:
                last_error = f"http_{resp.status_code}"
                continue
            if resp.status_code >= 400:
                raise ApiError(f"{method} {path} -> {resp.status_code}", resp.status_code)
            return resp
        raise ApiError(f"{method} {path} failed after {self._attempts} attempts ({last_error})")
