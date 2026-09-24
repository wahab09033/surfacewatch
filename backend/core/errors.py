"""Unhandled exceptions, turned into a response *inside* the middleware stack.

Why this exists rather than only the ``@app.exception_handler(Exception)`` that
FastAPI makes easy:

Starlette builds its stack as::

    ServerErrorMiddleware          <- outermost; owns the Exception handler
      RequestIdMiddleware
        SecurityHeadersMiddleware
          CORSMiddleware
            ErrorHandlingMiddleware   <- this module
              ExceptionMiddleware
                router

An unhandled exception propagates *upward*, so CORS and the security headers
never see it: they only decorate a response that comes back down through them.
``ServerErrorMiddleware`` catches the exception above all of them, calls the
handler, and sends that response straight out. The 500 a browser receives is
therefore missing ``Access-Control-Allow-Origin``, and the browser reports a
CORS failure instead of a server error — the frontend cannot tell "the API
crashed" from "the network is down", and the message the user sees is
misleading at exactly the moment it matters most.

Catching the exception one layer lower fixes it properly. The response is
synthesised *below* CORS and the security headers, so it travels back out
through both and arrives at the browser as a legible 500 with the usual
headers. The FastAPI handler is kept as a backstop for the narrow case of a
failure inside CORS or the header middleware themselves, where there is nothing
left beneath to catch it.
"""

from __future__ import annotations

import logging

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from core.request_context import get_request_id

__all__ = ["ErrorHandlingMiddleware", "internal_error_response"]

logger = logging.getLogger("surfacewatch.errors")


def internal_error_response() -> JSONResponse:
    """The one definition of the 500 body.

    Deliberately says nothing: stack traces, SQL fragments and driver messages
    disclose schema and infrastructure, so they stay in the log. The request id
    is the exception — it is meaningless to anyone who cannot already read the
    logs, and it is the only thing that lets a user connect the failure they saw
    to the traceback that explains it.
    """
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "request_id": get_request_id()},
    )


class ErrorHandlingMiddleware:
    """Return the generic 500 for anything the app did not handle itself.

    Raw ASGI rather than BaseHTTPMiddleware: this stack carries a WebSocket and
    streamed report downloads, and BaseHTTPMiddleware buffers the one and does
    not pass the other through at all.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        response_started = False

        async def track_start(message) -> None:  # type: ignore[no-untyped-def]
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, receive, track_start)
        except Exception:
            logger.exception(
                "unhandled error on %s %s", scope.get("method"), scope.get("path")
            )
            if response_started:
                # Headers and possibly part of the body are already on the wire.
                # A second response cannot be sent, and swallowing the exception
                # here would leave the client waiting on a body that never
                # finishes. Let it propagate so the server closes the connection
                # and the client sees a truncated response rather than a hang.
                raise
            await internal_error_response()(scope, receive, send)
