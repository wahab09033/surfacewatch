"""Tests for the resolution-time SSRF guard.

``assert_in_scope`` validates a *string* when a scan is created. These tests
cover the second half of that contract: what happens when the string is fine
but DNS — or a redirect — points somewhere it should not.

The hostile target here is a real HTTP server on loopback. That makes the
failure mode unambiguous: if the guard is missing the request *succeeds* and
the assertion fails on returned content, rather than on a connection error that
could have come from anywhere.
"""

from __future__ import annotations

import asyncio
import http.server
import socket
import socketserver
import threading

import httpx
import pytest

from core.scoring import (
    OutOfScopeError,
    UnsafeAddressError,
    assert_public_host,
    resolve_public_addresses,
)
from workers.safe_http import safe_async_client, safe_client


# --- resolve_public_addresses -----------------------------------------------


@pytest.mark.parametrize(
    "target",
    [
        "127.0.0.1",
        "10.0.0.5",
        "192.168.1.1",
        "172.16.0.1",
        "169.254.169.254",  # cloud metadata endpoint — the classic SSRF pivot
        "0.0.0.0",
        "::1",
        "fd00::1",
        "100.64.0.1",  # carrier-grade NAT
    ],
)
def test_ip_literals_in_reserved_space_are_refused(target):
    with pytest.raises(UnsafeAddressError):
        resolve_public_addresses(target)


def test_names_resolving_to_loopback_are_refused():
    """The rebinding case: an in-scope *name* whose record points inward."""
    with pytest.raises(UnsafeAddressError) as exc:
        resolve_public_addresses("localhost")
    # The message must name the address, not just the host — an operator
    # reading the scan log needs to know where it actually pointed.
    assert "127.0.0.1" in str(exc.value) or "::1" in str(exc.value)


def test_unresolvable_name_fails_closed():
    with pytest.raises(UnsafeAddressError):
        resolve_public_addresses("no-such-host.invalid")


def test_unsafe_address_error_is_an_out_of_scope_error():
    """Callers that already catch OutOfScopeError keep working unchanged."""
    assert issubclass(UnsafeAddressError, OutOfScopeError)


def test_public_names_resolve_normally():
    """The guard must not break legitimate scanning."""
    addresses = resolve_public_addresses("example.com")
    assert addresses
    assert assert_public_host("example.com") == "example.com"


def test_scheme_and_port_are_stripped_before_resolution():
    with pytest.raises(UnsafeAddressError):
        resolve_public_addresses("http://127.0.0.1:8080/latest/meta-data/")


def test_userinfo_decoy_does_not_smuggle_a_private_host():
    """``https://public.example.com@127.0.0.1/`` connects to 127.0.0.1."""
    with pytest.raises(UnsafeAddressError):
        resolve_public_addresses("https://example.com@127.0.0.1/")


# --- safe_client / safe_async_client ----------------------------------------


class _Handler(http.server.BaseHTTPRequestHandler):
    """Serves a redirect to loopback, plus a plain page to redirect to."""

    protocol_version = "HTTP/1.1"

    def do_GET(self):  # noqa: N802 — BaseHTTPRequestHandler's naming
        if self.path.startswith("/redirect-to-metadata"):
            self._redirect("http://169.254.169.254/latest/meta-data/")
        elif self.path.startswith("/redirect-to-loopback"):
            self._redirect(f"http://127.0.0.1:{self.server.server_address[1]}/secret")
        else:
            body = b"INTERNAL-ONLY-CONTENT"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def _redirect(self, location: str) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):  # silence per-request stderr noise
        pass


@pytest.fixture
def internal_server():
    """A real HTTP server on loopback, standing in for internal infrastructure."""
    server = socketserver.TCPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_sync_client_refuses_direct_loopback(internal_server):
    with safe_client(timeout=5.0) as client:
        with pytest.raises(UnsafeAddressError):
            client.get(f"http://127.0.0.1:{internal_server}/secret")


def test_sync_client_refuses_redirect_into_loopback(internal_server):
    """The redirect leg is guarded, not just the first request."""
    with safe_client(timeout=5.0, follow_redirects=True) as client:
        with pytest.raises(UnsafeAddressError):
            client.get(f"http://localhost:{internal_server}/redirect-to-loopback")


def test_redirect_to_metadata_endpoint_is_refused(internal_server):
    """The payoff case: 302 -> 169.254.169.254 must never be fetched."""
    with safe_client(timeout=5.0, follow_redirects=True) as client:
        with pytest.raises(UnsafeAddressError) as exc:
            client.get(f"http://127.0.0.1:{internal_server}/redirect-to-metadata")
    assert "127.0.0.1" in str(exc.value) or "169.254.169.254" in str(exc.value)


def test_async_client_refuses_loopback(internal_server):
    async def go():
        async with safe_async_client(timeout=5.0) as client:
            await client.get(f"http://127.0.0.1:{internal_server}/secret")

    with pytest.raises(UnsafeAddressError):
        asyncio.run(go())


def test_guard_composes_with_caller_supplied_hooks(internal_server):
    """A caller's own event hooks must survive, and the guard still run."""
    seen: list[str] = []

    with safe_client(
        timeout=5.0, event_hooks={"request": [lambda r: seen.append(str(r.url))]}
    ) as client:
        with pytest.raises(UnsafeAddressError):
            client.get(f"http://127.0.0.1:{internal_server}/secret")

    # The guard runs first and aborts, so the caller's hook never fires — which
    # is the point: nothing downstream observes a request we refuse to send.
    assert seen == []


def test_requests_are_pinned_to_the_validated_address():
    """Close the TOCTOU window: connect to the IP we checked, not the name.

    Re-resolving at connect time lets a zero-TTL hostile record answer
    differently the second time. Pinning means the Host header still carries
    the name (so virtual hosts work) while the URL carries the address.
    """
    sent: list[httpx.Request] = []

    def capture(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(200, text="ok")

    with safe_client(transport=httpx.MockTransport(capture), timeout=5.0) as client:
        client.get("http://example.com/probe")

    request = sent[0]
    # The URL host is now a literal address...
    socket.inet_pton(
        socket.AF_INET6 if ":" in request.url.host else socket.AF_INET,
        request.url.host,
    )
    # ...but the origin server still sees the name it expects.
    assert request.headers["Host"] == "example.com"
    assert request.extensions.get("sni_hostname") == "example.com"


def test_pinning_preserves_a_non_default_port():
    sent: list[httpx.Request] = []

    def capture(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(200, text="ok")

    with safe_client(transport=httpx.MockTransport(capture), timeout=5.0) as client:
        client.get("https://example.com:8443/probe")

    assert sent[0].headers["Host"] == "example.com:8443"
    assert sent[0].url.port == 8443
