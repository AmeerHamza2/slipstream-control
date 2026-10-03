"""HMAC-SHA256 service-to-service request signing, v1 (docs/CONTRACT.md).

    X-Slipstream-Service:   fleet-prober
    X-Slipstream-Timestamp: <unix seconds>
    X-Slipstream-Signature: v1=<hex(HMAC_SHA256(secret, f"{ts}.{METHOD}.{path}.{body}"))>

`path` is the URL path without the query string.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from collections.abc import Mapping
from urllib.parse import urlsplit

from fleet_prober import SERVICE_NAME

HEADER_SERVICE = "X-Slipstream-Service"
HEADER_TIMESTAMP = "X-Slipstream-Timestamp"
HEADER_SIGNATURE = "X-Slipstream-Signature"
SIGNATURE_VERSION = "v1"


def canonical_path(path_or_url: str) -> str:
    """Return the URL path with any scheme, host and query string removed."""
    return urlsplit(path_or_url).path or "/"


def compute_signature(secret: bytes, timestamp: int, method: str, path: str, body: bytes) -> str:
    message = b".".join(
        (str(timestamp).encode(), method.upper().encode(), canonical_path(path).encode(), body)
    )
    digest = hmac.new(secret, message, hashlib.sha256).hexdigest()
    return f"{SIGNATURE_VERSION}={digest}"


def sign(
    secret: bytes,
    method: str,
    path: str,
    body: bytes = b"",
    *,
    service: str = SERVICE_NAME,
    timestamp: int | None = None,
) -> dict[str, str]:
    """Return the three auth headers for a request. `body` must be the exact bytes sent."""
    ts = int(time.time()) if timestamp is None else timestamp
    return {
        HEADER_SERVICE: service,
        HEADER_TIMESTAMP: str(ts),
        HEADER_SIGNATURE: compute_signature(secret, ts, method, path, body),
    }


def verify(
    secret: bytes,
    headers: Mapping[str, str],
    method: str,
    path: str,
    body: bytes,
    *,
    now: int | None = None,
    tolerance_s: int = 300,
) -> bool:
    """Server-side check (used by tests and the fake api); constant-time compare."""
    lowered = {k.lower(): v for k, v in headers.items()}  # header names are case-insensitive
    try:
        ts = int(lowered[HEADER_TIMESTAMP.lower()])
        got = lowered[HEADER_SIGNATURE.lower()]
    except (KeyError, ValueError):
        return False
    current = int(time.time()) if now is None else now
    if abs(current - ts) > tolerance_s:
        return False
    expected = compute_signature(secret, ts, method, path, body)
    return hmac.compare_digest(expected.encode(), got.encode())
