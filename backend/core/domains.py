"""What counts as a domain an organisation may claim.

The rule lives here, in one place, because three callers need it and they must
agree: the registration schema (``schemas.auth.RegisterRequest``), the add-domain
schema (``schemas.domain.DomainAdd``), and the add-domain route. Two of those
used to carry their own copy of "must contain a dot" and nothing else.
"""

from __future__ import annotations

import ipaddress
import re

from core.scoring import is_private_address, normalise_host

MAX_DOMAIN_LENGTH = 253
_MAX_LABEL_LENGTH = 63

# A label: alphanumeric, internal hyphens allowed, no leading/trailing hyphen.
# Underscores are deliberately excluded — they are legal in DNS but not in
# hostnames, and a claim on "_foo.example.com" is never a real attack surface.
_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

# Registrable-suffix guard. `core.scoring.in_scope` matches by suffix, so a
# verified "com" would authorise every .com host on the internet.
#
# The real barrier is the DNS challenge — nobody can publish a TXT record under a
# public suffix they do not operate — so this list is defence in depth, not the
# control. It exists to fail the obvious cases immediately with a clear message
# rather than sending someone off to create a record that can never exist. It is
# deliberately not a complete Public Suffix List; that would mean a new
# dependency and a data file to keep current, for a check the DNS challenge
# already enforces.
_PUBLIC_SUFFIXES = frozenset(
    {
        # Generic
        "com", "net", "org", "info", "biz", "int", "edu", "gov", "mil",
        "io", "co", "ai", "app", "dev", "me", "tv", "cc", "xyz", "online",
        "site", "top", "shop", "cloud", "tech", "store", "blog",
        # Country-code
        "uk", "us", "eu", "de", "fr", "nl", "es", "it", "se", "no", "fi",
        "dk", "pl", "ch", "at", "be", "ie", "pt", "gr", "cz", "ro",
        "ca", "au", "nz", "jp", "cn", "in", "br", "mx", "ru", "za", "kr",
        "sg", "hk", "tr", "ae", "il", "ar", "cl", "id", "my", "th", "vn",
        # Common second-level registries
        "co.uk", "org.uk", "ac.uk", "gov.uk", "net.uk", "me.uk", "ltd.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au",
        "co.nz", "net.nz", "org.nz",
        "co.za", "org.za", "web.za",
        "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
        "com.br", "net.br", "org.br", "gov.br",
        "com.cn", "net.cn", "org.cn", "gov.cn",
        "co.in", "net.in", "org.in", "gov.in",
        "com.mx", "com.tr", "com.ar", "com.sg", "com.hk", "com.my",
        "com.tw", "com.pl", "com.ua", "com.ph", "com.vn", "com.co",
    }
)


class InvalidDomainError(ValueError):
    """Raised when a claimed domain can never be verified or scanned."""


def normalise_claimable_domain(value: str) -> str:
    """Normalise a user-supplied domain, or explain why it cannot be claimed.

    Accepts what people actually paste — ``https://Example.COM/path``, a trailing
    dot, a port — and returns the bare lowercase hostname.

    Raises ``InvalidDomainError`` with a message written for the person typing it.
    """
    domain = normalise_host(value)

    if not domain:
        raise InvalidDomainError("Enter a domain, e.g. example.com")

    if len(domain) > MAX_DOMAIN_LENGTH:
        raise InvalidDomainError(
            f"A domain cannot be longer than {MAX_DOMAIN_LENGTH} characters"
        )

    # An IP literal is never claimable. It has no zone to publish a TXT record
    # in, so the challenge could never be satisfied. Checked before the dot rule
    # because "8.8.8.8" would otherwise sail past it.
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise InvalidDomainError(
            "Enter a domain name, not an IP address. Ownership is proven with a "
            "DNS record, which an address has nowhere to live."
        )

    if "." not in domain:
        raise InvalidDomainError("Enter a fully-qualified domain, e.g. example.com")

    if is_private_address(domain):
        raise InvalidDomainError(
            f"{domain} is a private or reserved name and cannot be scanned"
        )

    if domain in _PUBLIC_SUFFIXES:
        raise InvalidDomainError(
            f"{domain} is a public suffix, not a domain you can own. Verifying it "
            f"would authorise scanning every domain under it. Enter the specific "
            f"domain you control, e.g. example.{domain}"
        )

    for label in domain.split("."):
        if not label:
            raise InvalidDomainError(f"{domain} has an empty label — check the dots")
        if len(label) > _MAX_LABEL_LENGTH:
            raise InvalidDomainError(
                f"'{label}' is longer than the {_MAX_LABEL_LENGTH}-character limit "
                "for one part of a domain"
            )
        if not _LABEL_RE.match(label):
            raise InvalidDomainError(
                f"'{label}' is not a valid part of a domain name — use letters, "
                "digits and hyphens, not starting or ending with a hyphen"
            )

    return domain


__all__ = [
    "InvalidDomainError",
    "MAX_DOMAIN_LENGTH",
    "normalise_claimable_domain",
]
