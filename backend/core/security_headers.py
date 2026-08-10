"""Response security headers.

This is a JSON API, so the headers that matter here are not the same set a
server-rendered HTML app needs. Each one below is included because it changes
the outcome of a specific attack against *this* application, and the ones that
would be cargo-cult are deliberately absent (see the bottom of this module).

The middleware sets headers on every response including errors, which is the
reason it is middleware rather than a dependency: a 401 from the auth layer or
a 500 from an unhandled exception never runs route dependencies, and those are
exactly the responses an attacker is most likely to be looking at.
"""

from __future__ import annotations

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from config import settings

__all__ = ["SecurityHeadersMiddleware", "security_headers"]


def security_headers(*, https: bool) -> dict[str, str]:
    """Build the header set. ``https`` gates the ones that only apply over TLS."""
    headers = {
        # The API returns JSON, but an endpoint that echoes user input (a scan
        # target, an org name in an error) served with a sniffable content type
        # can be coaxed into executing as HTML in older browsers. Turning off
        # sniffing costs nothing and removes the class.
        "X-Content-Type-Options": "nosniff",
        # No part of this API is meant to be framed. DENY rather than
        # SAMEORIGIN: nothing here frames anything else either.
        "X-Frame-Options": "DENY",
        # Referrer would otherwise carry the full URL — which for this API
        # includes scan and finding UUIDs — to any third-party host a response
        # links to. Origin-only on cross-origin, full path same-origin.
        "Referrer-Policy": "strict-origin-when-cross-origin",
        # A JSON API needs none of these. Denying them means a successful XSS
        # against a response rendered in a browser context cannot reach for the
        # camera, the mic, or the user's location.
        "Permissions-Policy": "geolocation=(), microphone=(), camera=(), payment=()",
        # Defence in depth for anything a browser does render directly from
        # this origin: /docs and /redoc in development, and any response an
        # attacker manages to get interpreted as a document. 'none' for
        # everything, since a JSON response legitimately loads nothing at all.
        #
        # frame-ancestors duplicates X-Frame-Options on purpose: the header is
        # the one older browsers honour, the directive is the one that is
        # actually standardised, and they cost one line each.
        "Content-Security-Policy": (
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        ),
    }

    if https:
        # Only meaningful over TLS, and actively harmful to send otherwise:
        # a browser that sees it on a plaintext development origin would pin
        # localhost to https for the whole max-age, which is a self-inflicted
        # outage that survives clearing the site's cookies and breaks every
        # other project served from that origin.
        headers["Strict-Transport-Security"] = (
            f"max-age={settings.hsts_max_age}; includeSubDomains"
        )

    return headers


class SecurityHeadersMiddleware:
    """Attach security headers to every response.

    Written against the raw ASGI interface rather than BaseHTTPMiddleware
    because this app serves a WebSocket (/ws/scan/{id}) and streams report
    downloads. BaseHTTPMiddleware wraps the response in a queue that breaks
    both — it does not pass websocket scopes through at all, and it buffers
    streaming bodies. Here anything that is not a plain HTTP request is handed
    straight to the app untouched.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        # The header values do not vary per request, so they are built once at
        # startup rather than per response.
        self._headers = [
            (k.lower().encode("latin-1"), v.encode("latin-1"))
            for k, v in security_headers(https=settings.is_production).items()
        ]

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                existing = {name for name, _ in message.get("headers", [])}
                # Never clobber a header a route set deliberately — the report
                # download sets its own Content-Disposition/Content-Type, and a
                # future route may need a narrower CSP than the default.
                message.setdefault("headers", []).extend(
                    (name, value) for name, value in self._headers if name not in existing
                )
            await send(message)

        await self.app(scope, receive, send_with_headers)


# Deliberately not set:
#
#   X-XSS-Protection — the header enabled a filter that was itself exploitable,
#   and every current browser has removed it. Sending "1; mode=block" is a
#   scanner-pleasing no-op at best.
#
#   X-Powered-By / Server suppression — uvicorn's Server header is set at the
#   protocol layer, below this middleware, and removing it is obscurity rather
#   than a control. Version numbers are what would matter, and it sends none.
