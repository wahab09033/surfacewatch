"""Request correlation.

Every HTTP request is given an id that appears in three places: the response
header, every log line written while that request is being handled, and the
body of a 500. That is the whole point — when a user reports "the scan page
broke", the id they can read off the screen is the one that finds the traceback
in the logs, without guessing from a timestamp which of several hundred
concurrent requests they meant.

The id is carried in a ContextVar rather than passed down as an argument. A
request id that has to be threaded through every service, repository and worker
helper is one that gets dropped in the first function somebody writes in a
hurry; a ContextVar is set once at the edge and read from anywhere below, and
because it is context-local it stays correct when the same process is handling
many requests at once.
"""

from __future__ import annotations

import contextvars
import logging
import uuid

from starlette.types import ASGIApp, Message, Receive, Scope, Send

__all__ = [
    "RequestIdMiddleware",
    "get_request_id",
    "new_request_id",
    "set_request_id",
    "use_incoming_id",
]

REQUEST_ID_HEADER = "X-Request-ID"

# None outside a request — startup, shutdown, Celery tasks, Alembic. Readers
# turn that into "-" rather than the string "None".
_request_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "request_id", default=None
)

# Long enough to be unguessable if a client ever echoes one back in a URL that
# ends up somewhere shared, short enough to read aloud in a bug report.
_MAX_INCOMING_LENGTH = 64


def new_request_id() -> str:
    return uuid.uuid4().hex


def set_request_id(value: str | None) -> contextvars.Token:
    return _request_id.set(value)


def get_request_id() -> str:
    return _request_id.get() or "-"


def use_incoming_id(raw: str | None) -> str:
    """Adopt a caller-supplied id, or mint one.

    The header is accepted because a request that is already being traced
    upstream — by Caddy, by a load balancer, by the frontend's own logger —
    should keep one id across the whole path rather than gaining a second one
    at this hop.

    It is validated rather than trusted. The value is reflected into a response
    header and into every log line for the request, and both are places where
    attacker-controlled text does damage: a newline in a header value is a
    response-splitting attempt, and a newline or a control character in a log
    line forges entries. Anything that is not a short run of unreserved
    characters is discarded and replaced.
    """
    if raw:
        candidate = raw.strip()
        if 0 < len(candidate) <= _MAX_INCOMING_LENGTH and all(
            c.isalnum() or c in "-_." for c in candidate
        ):
            return candidate
    return new_request_id()


def _install_record_factory() -> None:
    """Put the id on every LogRecord, wherever it is logged from.

    A logging.Filter attached to a handler would only cover handlers that
    remembered to add it, and a filter on the root *logger* would miss records
    that propagate up from child loggers — propagation reaches ancestor
    handlers directly and never runs their logger-level filters. The record
    factory is the one hook that every record passes through, so a format
    string can reference ``%(request_id)s`` unconditionally and never raise on
    a line logged outside a request.
    """
    existing = logging.getLogRecordFactory()

    def factory(*args, **kwargs) -> logging.LogRecord:
        record = existing(*args, **kwargs)
        record.request_id = get_request_id()
        return record

    logging.setLogRecordFactory(factory)


_install_record_factory()


class RequestIdMiddleware:
    """Assign a request id, expose it downstream, echo it on the way out.

    Raw ASGI for the same reason as SecurityHeadersMiddleware: this app serves a
    WebSocket and streams report downloads, and BaseHTTPMiddleware buffers the
    one and refuses the other.

    Sits outermost among the application's own middleware so the id is set
    before anything below it can log, and so the header is attached to every
    response — including the ones CORS rejects and the ones an error handler
    synthesises.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        self._header = REQUEST_ID_HEADER.lower().encode("latin-1")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        request_id = use_incoming_id(_header_value(scope, self._header))
        # Not reset afterwards. Each request runs in its own context, so the
        # value cannot leak into another one, and a reset would blank the id
        # for a background task still draining after the response is sent.
        set_request_id(request_id)

        if scope["type"] == "websocket":
            await self.app(scope, receive, send)
            return

        async def send_with_id(message: Message) -> None:
            if message["type"] == "http.response.start":
                message.setdefault("headers", []).append((self._header, request_id.encode("latin-1")))
            await send(message)

        await self.app(scope, receive, send_with_id)


def _header_value(scope: Scope, name: bytes) -> str | None:
    for key, value in scope.get("headers", []):
        if key == name:
            return value.decode("latin-1")
    return None
