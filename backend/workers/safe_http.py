"""HTTP clients that cannot be redirected into our own network.

``assert_in_scope`` validates the target *string* when a scan is created. That
is not enough for anything that opens a socket, for two reasons:

1.  **DNS rebinding.** An attacker who legitimately verified ``evil.example.com``
    controls its DNS and can point it at ``169.254.169.254``. The name passes
    every string check because the name really is in scope.
2.  **Redirects.** ``follow_redirects=True`` means an in-scope host can answer
    ``302 Location: http://169.254.169.254/latest/meta-data/`` and the scanner
    will fetch it — putting cloud credentials into a finding body.

Both are closed here, on every request and on every redirect hop:

*   the hostname is resolved and refused if any answer is a reserved address, and
*   the request is then **pinned** to that validated IP.

Pinning is what makes it airtight. Validating the name and then handing the name
back to the socket layer leaves a TOCTOU window: the OS resolves a second time at
connect time and a hostile nameserver with a zero TTL can answer differently. We
connect to the exact address we checked.

Pinning rewrites the URL, so the ``Host`` header and the TLS SNI value are set
back to the original name — otherwise every virtual host would break and every
certificate would fail to validate.
"""

from __future__ import annotations

import asyncio
import ipaddress
from typing import Any

import httpx

from core.scoring import UnsafeAddressError, resolve_public_addresses

__all__ = [
    "UnsafeAddressError",
    "safe_async_client",
    "safe_client",
]


def _preferred_address(addresses: list[str]) -> str:
    """Pin to IPv4 when the name has one; not every scanner host has v6 routing."""
    for address in addresses:
        if ipaddress.ip_address(address).version == 4:
            return address
    return addresses[0]


def _authority(url: httpx.URL) -> str:
    """``host`` or ``host:port`` — what the Host header should say for this URL."""
    host = url.host
    if ":" in host:  # bare IPv6 literal
        host = f"[{host}]"
    default = (url.scheme == "http" and url.port in (None, 80)) or (
        url.scheme == "https" and url.port in (None, 443)
    )
    return host if default else f"{host}:{url.port}"


def _pin(request: httpx.Request, addresses: list[str]) -> None:
    original = _authority(request.url)
    sni = request.url.host
    request.url = request.url.copy_with(host=_preferred_address(addresses))
    # Set both: httpx reads headers, and h11 writes whichever it finds.
    request.headers["Host"] = original
    request.extensions["sni_hostname"] = sni


def _guard(request: httpx.Request) -> list[str] | None:
    """Return the addresses to pin to, or None when the URL needs no rewrite.

    Raises ``UnsafeAddressError`` for anything that resolves into reserved
    space. A redirect hop lands here exactly like an initial request does.
    """
    host = request.url.host
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        # Already an IP — either one we pinned on a previous hop, or a literal
        # in a Location header. Either way it still has to be checked, but
        # there is nothing to rewrite.
        resolve_public_addresses(host)
        return None
    return resolve_public_addresses(host, port=request.url.port or 0)


def _sync_hook(request: httpx.Request) -> None:
    addresses = _guard(request)
    if addresses:
        _pin(request, addresses)


async def _async_hook(request: httpx.Request) -> None:
    # getaddrinfo blocks; keep it off the event loop.
    addresses = await asyncio.to_thread(_guard, request)
    if addresses:
        _pin(request, addresses)


def _with_hook(kwargs: dict[str, Any], hook: Any) -> dict[str, Any]:
    """Merge our guard into any event_hooks the caller passed, first in line."""
    hooks = dict(kwargs.pop("event_hooks", None) or {})
    hooks["request"] = [hook, *hooks.get("request", [])]
    return {**kwargs, "event_hooks": hooks}


def safe_client(**kwargs: Any) -> httpx.Client:
    """``httpx.Client`` that refuses to contact private/reserved addresses."""
    return httpx.Client(**_with_hook(kwargs, _sync_hook))


def safe_async_client(**kwargs: Any) -> httpx.AsyncClient:
    """``httpx.AsyncClient`` that refuses to contact private/reserved addresses."""
    return httpx.AsyncClient(**_with_hook(kwargs, _async_hook))
