"""DNS TXT proof-of-ownership checks.

Publishing a TXT record under a domain requires control of its DNS, which is the
closest thing to proof of ownership available without a human in the loop. This
module performs that check and nothing else — deciding what to do with the answer
belongs to ``routes.domains`` and the weekly re-verification task.

Everything here is async and uses ``dns.asyncresolver``, matching
``workers.subdomain_enum``, so a FastAPI handler awaits it directly with no
threadpool hop.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import dns.asyncresolver
import dns.exception
import dns.resolver

from models.domain_verification import APEX_PREFIX, CHALLENGE_LABEL

logger = logging.getLogger(__name__)

# Matches workers.subdomain_enum._DNS_TIMEOUT. A verification check is a single
# interactive request the user is waiting on, so it must fail fast rather than
# hold a request open on a domain whose nameservers are blackholing us.
_DNS_TIMEOUT = 3.0


@dataclass(frozen=True)
class TxtLookup:
    """Result of one TXT query.

    ``values`` empty with ``error`` None means the name resolved but has no TXT
    records — a real answer, and a different situation from ``error`` being set,
    which means we could not get an answer at all. Conflating the two produces
    the worst possible message: telling someone their record is missing when in
    fact our resolver timed out.
    """

    name: str
    values: tuple[str, ...] = ()
    error: str | None = None

    @property
    def resolved(self) -> bool:
        return self.error is None


@dataclass(frozen=True)
class DnsCheckResult:
    ok: bool
    error: str | None = None
    lookups: tuple[TxtLookup, ...] = field(default=())


def _resolver() -> dns.asyncresolver.Resolver:
    """A short-timeout resolver using the system nameservers."""
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = _DNS_TIMEOUT
    resolver.lifetime = _DNS_TIMEOUT
    return resolver


async def lookup_txt(
    name: str, resolver: dns.asyncresolver.Resolver | None = None
) -> TxtLookup:
    """Fetch the TXT values at ``name``.

    A TXT record is a sequence of character-strings, each capped at 255 bytes, and
    the RFC-correct reading is their concatenation. Our tokens are 43 characters
    so they never split, but some DNS panels wrap long values anyway and joining
    costs nothing.
    """
    resolver = resolver or _resolver()
    try:
        answer = await resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        # Authoritative "nothing here". Not an error — the caller reports it as a
        # missing record, which is the common case while DNS propagates.
        return TxtLookup(name=name)
    except dns.resolver.NoNameservers as exc:
        # Every nameserver for the zone refused or failed (typically SERVFAIL,
        # often a broken DNSSEC chain). We genuinely do not know whether the
        # record is there.
        return TxtLookup(name=name, error=f"the nameservers for {name} did not answer ({exc})")
    except dns.exception.Timeout:
        return TxtLookup(name=name, error=f"the DNS lookup for {name} timed out")
    except dns.exception.DNSException as exc:
        return TxtLookup(name=name, error=f"the DNS lookup for {name} failed ({exc})")

    values: list[str] = []
    for rdata in answer:
        try:
            joined = b"".join(rdata.strings).decode("utf-8", errors="replace").strip()
        except (AttributeError, UnicodeError):  # pragma: no cover — defensive
            continue
        if joined:
            values.append(joined)
    return TxtLookup(name=name, values=tuple(values))


async def check_domain_token(
    domain: str, token: str, resolver: dns.asyncresolver.Resolver | None = None
) -> DnsCheckResult:
    """Look for ``token`` published in DNS for ``domain``.

    Two accepted locations, checked in order:

    1. ``_surfacewatch-challenge.<domain>`` TXT = the bare token.
    2. ``<domain>`` TXT = ``surfacewatch-verification=<token>`` — the apex
       fallback, for DNS panels that will not create underscore labels.

    The apex is only consulted if the dedicated label did not match, so the common
    case is a single query.
    """
    resolver = resolver or _resolver()

    challenge_name = f"{CHALLENGE_LABEL}.{domain}"
    dedicated = await lookup_txt(challenge_name, resolver)
    if token in dedicated.values:
        return DnsCheckResult(ok=True, lookups=(dedicated,))

    apex = await lookup_txt(domain, resolver)
    if f"{APEX_PREFIX}{token}" in apex.values:
        return DnsCheckResult(ok=True, lookups=(dedicated, apex))

    lookups = (dedicated, apex)
    return DnsCheckResult(ok=False, error=_explain(domain, dedicated, apex), lookups=lookups)


def _explain(domain: str, dedicated: TxtLookup, apex: TxtLookup) -> str:
    """Turn a failed check into something actionable.

    The three outcomes send someone to different places: a lookup failure means
    wait and retry, no record means go create one, and a record that exists but
    does not match usually means a stale value from an earlier attempt.
    """
    # A lookup we could not complete is reported as exactly that. Saying "no
    # record found" here would be a guess, and one that sends the user to check
    # DNS they may have configured perfectly.
    if not dedicated.resolved and not apex.resolved:
        return (
            f"Could not check DNS for {domain}: {dedicated.error}. "
            "This is a lookup failure, not a missing record — try again shortly."
        )

    # Any TXT records at all, at either location?
    found = [v for lookup in (dedicated, apex) for v in lookup.values]
    if not found:
        return (
            f"No TXT record found at {dedicated.name} (or on {domain} itself). "
            "If you have just added it, DNS can take a few minutes to propagate."
        )

    return (
        f"Found {len(found)} TXT record(s) for {domain}, but none matched the "
        "expected value. A stale record from an earlier attempt is the usual "
        "cause — check the value matches exactly, with no quotes or spaces."
    )


__all__ = [
    "DnsCheckResult",
    "TxtLookup",
    "check_domain_token",
    "lookup_txt",
]
