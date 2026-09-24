"""Request ids, and the 500 that CORS is allowed to see.

Two things are being protected here, neither of which any other test in the
suite would notice if it broke:

1. Every response carries an X-Request-ID, and a request that already has one
   keeps it, so a trace survives the hop rather than restarting at this service.
   The incoming value is attacker-controlled and is reflected into a response
   header and into log lines, so it is validated rather than echoed.

2. An unhandled exception produces a 500 that still carries the CORS and
   security headers. Starlette's default arrangement puts the catch-all handler
   *above* CORS, so the response it synthesises never passes back down through
   it and the browser reports a CORS failure instead of a server error. The
   whole point of ErrorHandlingMiddleware is that this cannot happen, and a
   middleware reordering in main.py is exactly the kind of change that would
   silently undo it.
"""

from __future__ import annotations

import logging

import pytest
from fastapi.middleware.cors import CORSMiddleware

from config import settings
from core.request_context import (
    REQUEST_ID_HEADER,
    get_request_id,
    new_request_id,
    use_incoming_id,
)

ALLOWED_ORIGIN = settings.cors_origin_list[0]


@pytest.fixture
def boom_route():
    """A route that raises, mounted on the real app for the duration of a test.

    Adding to the live app rather than building a lookalike: the bug this
    guards against is a property of the *real* middleware stack, and a
    stand-in app assembled in the test would be free to get the ordering right
    while main.py got it wrong.
    """
    from main import app

    async def boom() -> None:
        raise RuntimeError("deliberate failure for the error-path tests")

    app.add_api_route("/__test/boom", boom, methods=["GET"])
    try:
        yield "/__test/boom"
    finally:
        app.router.routes = [r for r in app.router.routes if getattr(r, "path", "") != "/__test/boom"]


# --- the id itself ----------------------------------------------------------


def test_an_incoming_id_is_adopted():
    assert use_incoming_id("abc-123_XYZ.9") == "abc-123_XYZ.9"


def test_a_missing_id_is_generated():
    generated = use_incoming_id(None)
    assert generated and generated != "None"
    # Two calls must not collide, which a constant would.
    assert generated != use_incoming_id(None)


@pytest.mark.parametrize(
    "hostile",
    [
        "",
        "   ",
        "a" * 65,
        "abc\ndef",  # log injection: forges a second log line
        "abc\r\nX-Evil: 1",  # response splitting: forges a second header
        "abc def",
        'abc"def',
    ],
)
def test_a_hostile_id_is_discarded_not_reflected(hostile):
    """The value ends up in a response header and in every log line for the
    request. A newline in a header is response splitting; a newline in a log
    line forges entries; both are refused, and the caller gets a fresh id
    rather than an error, because a bad correlation header is not worth
    failing a request over."""
    result = use_incoming_id(hostile)
    assert result != hostile
    assert "\n" not in result and "\r" not in result and " " not in result
    assert len(result) == 32  # a generated uuid4 hex


def test_the_record_factory_is_installed_for_every_logger():
    """main.py's format string interpolates %(request_id)s. If the factory were
    missing, logging would swallow the error and print "--- Logging error ---"
    in place of every line — a service that appears to log nothing."""
    record = logging.getLogger("anything.at.all").makeRecord(
        "anything.at.all", logging.INFO, __file__, 1, "msg", None, None
    )
    assert hasattr(record, "request_id")


@pytest.mark.asyncio
async def test_every_response_carries_an_id(client):
    for path in ("/health", "/no/such/route"):
        response = await client.get(path)
        assert request_id_of(response), f"{path} came back without a request id"


@pytest.mark.asyncio
async def test_a_supplied_id_is_echoed(client):
    response = await client.get("/health", headers={REQUEST_ID_HEADER: "trace-me-42"})
    assert response.headers[REQUEST_ID_HEADER] == "trace-me-42"


@pytest.mark.asyncio
async def test_a_hostile_id_never_reaches_the_response_header(client):
    response = await client.get(
        "/health", headers={REQUEST_ID_HEADER: "abc\r\nX-Injected: yes"}
    )
    assert "X-Injected" not in response.headers
    assert request_id_of(response) != "abc"


# --- the 500 that CORS must be able to read ---------------------------------


@pytest.mark.asyncio
async def test_a_500_still_carries_cors_headers(client, boom_route):
    """The regression this module exists for.

    Without ErrorHandlingMiddleware the 500 is synthesised above CORSMiddleware
    and comes back with no Access-Control-Allow-Origin, so a browser reports a
    CORS error and the frontend cannot distinguish "the API crashed" from "the
    network is down".
    """
    response = await client.get(boom_route, headers={"Origin": ALLOWED_ORIGIN})

    assert response.status_code == 500
    assert response.headers.get("access-control-allow-origin") == ALLOWED_ORIGIN
    # Credentialed requests need this too, and CORS only sets it when it has
    # decided to allow the origin at all — so it is a second, independent
    # signal that CORS actually processed the response.
    assert response.headers.get("access-control-allow-credentials") == "true"


@pytest.mark.asyncio
async def test_a_500_still_carries_security_headers(client, boom_route):
    """The same bug, one layer out: SecurityHeadersMiddleware is above CORS, so
    a response synthesised above *it* would miss these too."""
    response = await client.get(boom_route)
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"


@pytest.mark.asyncio
async def test_a_500_does_not_leak_the_exception(client, boom_route):
    response = await client.get(boom_route)
    body = response.text
    assert "RuntimeError" not in body
    assert "deliberate failure" not in body
    assert response.json()["detail"] == "Internal server error"


@pytest.mark.asyncio
async def test_a_500_quotes_the_same_id_as_the_header(client, boom_route):
    """The id is only useful if the one the user reads off the screen is the one
    in the log line. Same value in both places, or the feature is decoration."""
    response = await client.get(boom_route)
    assert response.json()["request_id"] == request_id_of(response)
    assert request_id_of(response) != "-"


def test_the_id_is_absent_outside_a_request():
    """Startup, shutdown and Celery tasks log on a context with no request. The
    format string must render there rather than raise."""
    assert get_request_id() == "-"
    formatted = "%(request_id)s" % {"request_id": get_request_id()}
    assert formatted == "-"
    assert new_request_id() != new_request_id()


@pytest.mark.asyncio
async def test_without_the_error_middleware_the_cors_headers_are_lost():
    """Characterisation, not a guard: this asserts a *broken* stack stays broken.

    It is here as the evidence for why ErrorHandlingMiddleware exists at all,
    in the place someone tempted to delete it as redundant will look. Starlette
    puts its catch-all handler above CORS, so a 500 synthesised there never
    passes back down through it — the test below is the same request against the
    same stack minus one layer, and it comes back with no origin header at all.

    If a future Starlette release moves the handler, this test fails, and that
    is the signal that the middleware in core/errors.py can be reconsidered.
    """
    from starlette.applications import Starlette
    from starlette.routing import Route

    async def boom(request):  # type: ignore[no-untyped-def]
        raise RuntimeError("x")

    degenerate = Starlette(routes=[Route("/boom", boom)])
    degenerate.add_middleware(
        CORSMiddleware,
        allow_origins=[ALLOWED_ORIGIN],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    import httpx

    transport = httpx.ASGITransport(app=degenerate, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as ac:
        response = await ac.get("/boom", headers={"Origin": ALLOWED_ORIGIN})

    assert response.status_code == 500
    assert "access-control-allow-origin" not in response.headers


def test_the_app_middleware_order_is_innermost_error_handler_first():
    """A structural assertion, deliberately. The behaviour above depends on
    ErrorHandlingMiddleware wrapping the router from the inside and
    RequestIdMiddleware sitting outside everything; both are one careless
    add_middleware call away from being reversed, and neither ordering mistake
    shows up as anything but a confusing symptom in a browser."""
    from main import app

    names = [m.cls.__name__ for m in app.user_middleware]
    assert names == [
        "RequestIdMiddleware",
        "SecurityHeadersMiddleware",
        "CORSMiddleware",
        "ErrorHandlingMiddleware",
    ]


def request_id_of(response) -> str:  # type: ignore[no-untyped-def]
    return response.headers.get(REQUEST_ID_HEADER.lower(), "")
