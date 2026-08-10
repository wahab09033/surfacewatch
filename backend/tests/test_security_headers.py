"""Tests for the response security headers.

The interesting cases are not "the header is present" but the ones where a
security header is either missing where it counts or set where it does harm:

*   error responses carry them too (a 401 never runs route dependencies),
*   HSTS is absent in development (pinning localhost to https is a
    self-inflicted outage that survives clearing site data),
*   the WebSocket still connects (the middleware sees a scope type it must
    pass through untouched), and
*   a header a route set for itself is not clobbered.
"""

from __future__ import annotations

import pytest

from config import settings
from core.security_headers import security_headers

EXPECTED = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
}


@pytest.mark.anyio
async def test_headers_are_present_on_a_normal_response(client):
    response = await client.get("/health")
    assert response.status_code == 200
    for name, value in EXPECTED.items():
        assert response.headers.get(name) == value, name
    assert "default-src 'none'" in response.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


@pytest.mark.anyio
async def test_headers_are_present_on_an_error_response(client):
    """The reason this is middleware and not a dependency.

    A 401 is produced by the auth layer before any route dependency runs, and
    an unauthenticated response is exactly the one an attacker is looking at.
    """
    response = await client.get("/api/auth/me")
    assert response.status_code == 401
    for name, value in EXPECTED.items():
        assert response.headers.get(name) == value, name


@pytest.mark.anyio
async def test_headers_are_present_on_a_404(client):
    response = await client.get("/no-such-route")
    assert response.status_code == 404
    assert response.headers.get("x-content-type-options") == "nosniff"


@pytest.mark.anyio
async def test_headers_survive_a_rate_limited_response(client):
    """429s come from a middleware-adjacent raise; they must be covered too."""
    limit = settings.rate_limit_register_per_ip
    response = None
    for i in range(limit + 2):
        response = await client.post(
            "/api/auth/register",
            json={
                "org_name": f"Hdr {i}",
                "domain": f"hdr{i}.example",
                "email": f"hdr{i}@hdr{i}.example",
                "password": "Headers-P4ssw0rd!",
            },
        )
    assert response.status_code == 429
    assert response.headers.get("x-frame-options") == "DENY"


# --- HSTS is conditional ----------------------------------------------------


def test_hsts_is_absent_outside_production():
    """Sending HSTS over plaintext http://localhost is actively harmful.

    A browser that sees it pins localhost to https for the max-age — two years
    here — and clearing cookies does not undo it. Every developer on the
    project would lose the local stack.
    """
    assert settings.is_production is False
    assert "Strict-Transport-Security" not in security_headers(https=False)


def test_hsts_is_set_when_serving_over_https():
    header = security_headers(https=True).get("Strict-Transport-Security")
    assert header is not None
    assert "includeSubDomains" in header
    # Long enough to be meaningful rather than a token value.
    max_age = int(header.split("max-age=")[1].split(";")[0])
    assert max_age >= 31_536_000


@pytest.mark.anyio
async def test_live_response_has_no_hsts_in_development(client):
    response = await client.get("/health")
    assert "strict-transport-security" not in response.headers


# --- must not break the rest of the app -------------------------------------


def test_websocket_still_connects_through_the_middleware():
    """BaseHTTPMiddleware would have broken this, which is why it is not used.

    The middleware must hand any non-http scope straight to the app. A
    regression here takes out live scan streaming, and no HTTP test would
    notice.
    """
    from fastapi.testclient import TestClient
    from starlette.websockets import WebSocketDisconnect

    from main import WS_UNAUTHORIZED, app

    with TestClient(app) as tc:
        # No token. Reaching the handler and being closed by its own auth check
        # is the proof the scope passed through intact: a middleware that
        # mishandled it would fail before the handler ever ran, with something
        # other than this application-defined close code.
        with pytest.raises(WebSocketDisconnect) as exc_info:
            with tc.websocket_connect("/ws/scan/00000000-0000-0000-0000-000000000000"):
                pass
        assert exc_info.value.code == WS_UNAUTHORIZED


@pytest.mark.anyio
async def test_cors_headers_are_not_disturbed(client):
    """The security middleware wraps CORS; it must not eat its headers."""
    origin = settings.cors_origin_list[0]
    response = await client.options(
        "/api/auth/login",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert response.headers.get("access-control-allow-origin") == origin
    # ...and the preflight reply is itself protected.
    assert response.headers.get("x-content-type-options") == "nosniff"


@pytest.mark.anyio
async def test_route_set_headers_win(client):
    """A 429 sets Retry-After; the middleware must not overwrite route headers."""
    limit = settings.rate_limit_register_per_ip
    response = None
    for i in range(limit + 2):
        response = await client.post(
            "/api/auth/register",
            json={
                "org_name": f"Keep {i}",
                "domain": f"keep{i}.example",
                "email": f"keep{i}@keep{i}.example",
                "password": "Headers-P4ssw0rd!",
            },
        )
    assert response.status_code == 429
    assert int(response.headers["retry-after"]) > 0
