"""Risk scoring and scan-scope validation."""

from __future__ import annotations

import ipaddress
import socket
from typing import Any, Iterable

from models.base import Severity

# --- Risk scoring -----------------------------------------------------------

# Ports that materially raise exposure when reachable from the internet.
_RISKY_PORTS: dict[int, float] = {
    21: 6.0,    # FTP, usually cleartext
    23: 10.0,   # Telnet
    445: 9.0,   # SMB
    3389: 8.0,  # RDP
    3306: 7.0,  # MySQL
    5432: 7.0,  # PostgreSQL
    27017: 7.0, # MongoDB
    6379: 8.0,  # Redis, frequently unauthenticated
    9200: 7.0,  # Elasticsearch
    11211: 7.0, # Memcached
    5900: 7.0,  # VNC
    2375: 9.0,  # Docker API
    22: 2.0,    # SSH — expected, but still surface
    25: 3.0,
}
_DEFAULT_PORT_WEIGHT = 1.0
_EXPECTED_WEB_PORTS = {80, 443, 8080, 8443}

MAX_RISK_SCORE = 100.0


def score_asset(
    *, findings: Iterable[Severity], open_ports: Iterable[int]
) -> float:
    """Composite 0–100 risk score for one asset.

    Severity weights dominate; port exposure contributes a smaller surface
    term. The result is capped so a host with 200 findings does not swamp the
    ranking against one with three criticals.
    """
    finding_score = sum(sev.weight for sev in findings)

    port_score = 0.0
    for port in open_ports:
        if port in _EXPECTED_WEB_PORTS:
            port_score += 0.5
        else:
            port_score += _RISKY_PORTS.get(port, _DEFAULT_PORT_WEIGHT)

    total = finding_score + min(port_score, 25.0)
    return round(min(total, MAX_RISK_SCORE), 1)


def port_exposure_severity(port: int) -> Severity:
    """Severity for an "exposed service" finding raised by the port scanner."""
    weight = _RISKY_PORTS.get(port)
    if weight is None:
        return Severity.INFO
    if weight >= 9.0:
        return Severity.HIGH
    if weight >= 6.0:
        return Severity.MEDIUM
    if weight >= 2.0:
        return Severity.LOW
    return Severity.INFO


# --- Scan scope guard -------------------------------------------------------


class OutOfScopeError(ValueError):
    """Raised when a target is not covered by the org's verified domains."""


# Ranges an internet-facing ASM scan must never touch — they belong to the
# host's own network, not the customer's attack surface.
_FORBIDDEN_NETWORKS = [
    ipaddress.ip_network(n)
    for n in (
        "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "169.254.0.0/16", "0.0.0.0/8", "100.64.0.0/10", "224.0.0.0/4",
        "::1/128", "fc00::/7", "fe80::/10",
    )
]


# Hostnames that resolve to the loopback interface or to internal-only names.
# is_private_address() only understands IP literals, so a target typed as a
# name would otherwise sail past it — including when ALLOW_ARBITRARY_TARGETS
# is on for a lab deployment, which skips the domain check entirely.
_FORBIDDEN_HOSTNAMES = frozenset(
    {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}
)

# Suffixes reserved for internal networks; scanning them means scanning the
# scanner's own infrastructure, never a customer's public attack surface.
_FORBIDDEN_SUFFIXES = (".localhost", ".local", ".internal", ".localdomain", ".home.arpa")


def is_private_address(value: str) -> bool:
    """True for loopback/private/reserved targets, given as an IP *or* a name."""
    host = value.strip().lower().strip(".")
    if not host:
        return False
    if host in _FORBIDDEN_HOSTNAMES or host.endswith(_FORBIDDEN_SUFFIXES):
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(addr in net for net in _FORBIDDEN_NETWORKS)


def normalise_host(target: str) -> str:
    """Strip scheme, credentials, path, port and trailing dot from a target."""
    host = target.strip().lower()
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    # user:pass@host — keep the host, drop the credentials.
    if "@" in host:
        host = host.rsplit("@", 1)[1]

    # Bracketed IPv6, optionally with a port: [::1] or [fe80::1]:8443. Unwrap
    # it so the address reaches is_private_address() as a bare literal.
    if host.startswith("["):
        inner, _, _ = host[1:].partition("]")
        return inner.strip(".")

    if host.count(":") == 1:  # host:port — bare IPv6 has more than one colon
        host = host.split(":", 1)[0]
    return host.strip(".")


def in_scope(host: str, allowed_domains: Iterable[str]) -> bool:
    """True when ``host`` is one of the allowed domains or a subdomain of one."""
    host = normalise_host(host)
    if not host:
        return False
    for domain in allowed_domains:
        d = (domain or "").lower().strip(".")
        if d and (host == d or host.endswith(f".{d}")):
            return True
    return False


def assert_in_scope(
    host: str, allowed_domains: Iterable[str], *, allow_arbitrary: bool = False
) -> str:
    """Validate a target before any packet is sent.

    This is the guard rail that keeps one tenant from aiming the scanner at
    infrastructure it has no authorisation to test. ``allow_arbitrary`` exists
    for lab deployments and is off by default.

    This checks the *name*. A name that passes here can still resolve to a
    private address, so anything that opens a socket must additionally call
    ``resolve_public_addresses`` / ``assert_public_host``.
    """
    host = normalise_host(host)
    if not host:
        raise OutOfScopeError("Empty target")
    if is_private_address(host):
        raise OutOfScopeError(f"{host} is a private/reserved address and cannot be scanned")
    if allow_arbitrary:
        return host
    if not in_scope(host, allowed_domains):
        raise OutOfScopeError(
            f"{host} is not covered by this organisation's verified domains "
            f"({', '.join(allowed_domains) or 'none configured'}). "
            "Add and verify the domain before scanning it."
        )
    return host


# --- Resolution-time guard --------------------------------------------------
#
# assert_in_scope() validates a string. DNS decides what that string actually
# reaches, and the two can disagree — either by accident (a customer's staging
# CNAME pointing at RFC1918) or deliberately: an attacker who controls DNS for
# a domain they have legitimately verified can point it at 169.254.169.254 and
# turn the scanner into an SSRF proxy against our own infrastructure. The name
# passes every string check because the name really is in scope.
#
# So every code path that opens a socket resolves first and refuses the
# connection when the answer is a reserved address.


class UnsafeAddressError(OutOfScopeError):
    """Raised when a hostname resolves to a private/reserved address."""


def resolve_public_addresses(host: str, *, port: int = 0) -> list[str]:
    """Resolve ``host`` and return its addresses, or raise if any is private.

    Fails closed on a mixed answer set rather than filtering: a name that
    returns both a public and a private address is either misconfigured or
    hostile, and connecting to "just the public ones" leaves a TOCTOU window —
    the OS resolves again at connect time and may pick a different record.
    """
    host = normalise_host(host)
    if not host:
        raise UnsafeAddressError("Empty host")

    # An IP literal needs no lookup; is_private_address already covers it.
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if is_private_address(host):
            raise UnsafeAddressError(f"{host} is a private/reserved address")
        return [host]

    try:
        infos = socket.getaddrinfo(host, port or None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise UnsafeAddressError(f"{host} could not be resolved: {exc}") from exc

    addresses = sorted({info[4][0] for info in infos})
    if not addresses:
        raise UnsafeAddressError(f"{host} resolved to no addresses")

    unsafe = [a for a in addresses if is_private_address(a)]
    if unsafe:
        raise UnsafeAddressError(
            f"{host} resolves to a private/reserved address ({', '.join(unsafe)}) "
            "and will not be contacted"
        )
    return addresses


def assert_public_host(host: str, *, port: int = 0) -> str:
    """Resolve-and-check wrapper for callers that only need the hostname back."""
    resolve_public_addresses(host, port=port)
    return normalise_host(host)


# --- Aggregation helpers ----------------------------------------------------


def severity_breakdown(severities: Iterable[Severity]) -> dict[str, int]:
    counts: dict[str, int] = {s.value: 0 for s in Severity}
    for sev in severities:
        counts[sev.value] = counts.get(sev.value, 0) + 1
    return counts


def summarise_ports(ports: Iterable[dict[str, Any]]) -> list[int]:
    return sorted({p["port"] for p in ports if p.get("state") == "open" and "port" in p})


__all__ = [
    "MAX_RISK_SCORE",
    "OutOfScopeError",
    "UnsafeAddressError",
    "assert_in_scope",
    "assert_public_host",
    "in_scope",
    "is_private_address",
    "normalise_host",
    "port_exposure_severity",
    "resolve_public_addresses",
    "score_asset",
    "severity_breakdown",
    "summarise_ports",
]
