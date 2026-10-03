import hashlib
import hmac

from fleet_prober import signing

SECRET = b"test-prober-secret"
BODY = b'{"prober_id":"prober-eu-1","observed_at":"2026-10-02T12:00:00Z","results":[]}'


def test_known_vector_matches_independent_hmac() -> None:
    ts = 1790000000
    expected = hmac.new(
        SECRET,
        b"1790000000.POST./internal/v1/servers/heartbeats." + BODY,
        hashlib.sha256,
    ).hexdigest()

    headers = signing.sign(SECRET, "post", "/internal/v1/servers/heartbeats", BODY, timestamp=ts)

    assert headers == {
        "X-Slipstream-Service": "fleet-prober",
        "X-Slipstream-Timestamp": "1790000000",
        "X-Slipstream-Signature": f"v1={expected}",
    }


def test_get_with_empty_body_and_query_string_stripped() -> None:
    ts = 1790000000
    expected = hmac.new(SECRET, b"1790000000.GET./internal/v1/servers.", hashlib.sha256)
    sig = signing.compute_signature(SECRET, ts, "GET", "/internal/v1/servers?x=1", b"")
    assert sig == f"v1={expected.hexdigest()}"
    # A full URL signs only its path.
    assert sig == signing.compute_signature(
        SECRET, ts, "GET", "https://api.example/internal/v1/servers?x=1", b""
    )


def test_verify_round_trip_and_rejections() -> None:
    now = 1790000000
    path = "/internal/v1/servers/heartbeats"
    h = signing.sign(SECRET, "POST", path, BODY, timestamp=now)
    assert signing.verify(SECRET, h, "POST", path, BODY, now=now)
    assert not signing.verify(SECRET, h, "POST", path, BODY + b" ", now=now)  # body tamper
    assert not signing.verify(b"other", h, "POST", path, BODY, now=now)  # wrong secret
    assert not signing.verify(SECRET, h, "GET", path, BODY, now=now)  # method
    assert not signing.verify(SECRET, h, "POST", path, BODY, now=now + 301)  # stale
    assert signing.verify(SECRET, h, "POST", path, BODY, now=now + 300)
