"""Subdomain enumeration.

Three passive/semi-passive sources, cheapest first:

1. Certificate transparency logs (crt.sh) — passive, no traffic to the target.
2. DNS bruteforce over a built-in wordlist — resolver traffic only.
3. Zone-transfer attempt (AXFR) against the authoritative nameservers — this is
   a misconfiguration check, and a successful transfer is itself a finding.

Every candidate is filtered through the org's scope guard before it is stored,
and wildcard DNS is detected so a catch-all record does not manufacture
thousands of phantom assets.
"""

from __future__ import annotations

import asyncio
import random
import string
import uuid
from datetime import datetime, timezone
from typing import Any

import dns.asyncresolver
import dns.exception
# Imported explicitly rather than relying on dnspython's internal import graph:
# dns.resolver and dns.query happen to be pulled in by asyncresolver/zone today,
# but that is an implementation detail and would break silently if it changed.
import dns.query
import dns.resolver
import dns.zone
import httpx
from celery import shared_task
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from config import settings
from core.scoring import (
    UnsafeAddressError,
    in_scope,
    is_private_address,
    normalise_host,
    resolve_public_addresses,
)
from db.database import session_scope
from models import Asset, AssetStatus, Finding, Severity
from workers.context import ScanContext, run_async
from workers.safe_http import safe_client
from workers.wordlists import SUBDOMAIN_WORDLIST

STAGE = "subdomain_enum"

# Concurrency for DNS resolution. High is fine — these are small UDP queries —
# but we stay well under typical resolver rate limits.
_DNS_CONCURRENCY = 50
_DNS_TIMEOUT = 3.0


# --- Resolution helpers -----------------------------------------------------


def _resolver() -> dns.asyncresolver.Resolver:
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = _DNS_TIMEOUT
    resolver.lifetime = _DNS_TIMEOUT
    return resolver


async def _resolve_a(hostname: str, resolver: dns.asyncresolver.Resolver) -> list[str]:
    """Return A/AAAA addresses for a hostname, or [] if it does not resolve."""
    addresses: list[str] = []
    for rdtype in ("A", "AAAA"):
        try:
            answer = await resolver.resolve(hostname, rdtype)
            addresses.extend(r.address for r in answer)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            continue
        except (dns.exception.Timeout, dns.exception.DNSException):
            continue
    return addresses


async def _detect_wildcard(domain: str, resolver: dns.asyncresolver.Resolver) -> set[str]:
    """Probe three random labels; any addresses they share are wildcard answers.

    Without this a catch-all A record makes every bruteforce candidate look
    live, which floods the inventory with hosts that do not exist.
    """
    wildcard_ips: set[str] = set()
    for _ in range(3):
        label = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
        addresses = await _resolve_a(f"{label}.{domain}", resolver)
        wildcard_ips.update(addresses)
    return wildcard_ips


# --- Source 1: certificate transparency -------------------------------------


def _fetch_crtsh(ctx: ScanContext) -> set[str]:
    """Pull names from crt.sh. Failure is non-fatal: DNS bruteforce still runs."""
    url = "https://crt.sh/"
    params = {"q": f"%.{ctx.target}", "output": "json"}
    names: set[str] = set()
    try:
        # crt.sh is a fixed host, so this is not the SSRF path the target can
        # steer — but a hijacked or compromised upstream redirecting us inward
        # is exactly what the guard is for, and it costs nothing here.
        with safe_client(
            timeout=30.0, headers={"User-Agent": settings.http_user_agent}, follow_redirects=True
        ) as client:
            response = client.get(url, params=params)
            if response.status_code != 200:
                ctx.warn(f"crt.sh returned HTTP {response.status_code}; skipping CT source")
                return names
            for entry in response.json():
                # name_value may hold several newline-separated SANs.
                for raw in str(entry.get("name_value", "")).splitlines():
                    candidate = normalise_host(raw.strip().lstrip("*."))
                    if candidate:
                        names.add(candidate)
    except (httpx.HTTPError, ValueError) as exc:
        ctx.warn(f"Certificate transparency lookup failed: {exc}")
    return names


# --- Source 3: zone transfer ------------------------------------------------


def _try_zone_transfer(ctx: ScanContext) -> tuple[set[str], list[str]]:
    """Attempt AXFR against each authoritative NS.

    Returns discovered names plus the nameservers that allowed the transfer —
    an open AXFR leaks the entire zone and is reported as a finding.
    """
    names: set[str] = set()
    leaking: list[str] = []
    try:
        ns_answer = dns.resolver.resolve(ctx.target, "NS", lifetime=_DNS_TIMEOUT)
        nameservers = [str(r.target).strip(".") for r in ns_answer]
    except dns.exception.DNSException as exc:
        ctx.debug(f"Could not list nameservers for {ctx.target}: {exc}")
        return names, leaking

    for ns in nameservers:
        # NS records are attacker-controlled zone data: a hostile zone can
        # point them at internal addresses (169.254.169.254, 127.0.0.1, ...)
        # and turn the transfer attempt into a connection into our own
        # network. Resolve and pin like every other socket path, and skip
        # nameservers that do not resolve to public addresses.
        try:
            ns_addresses = resolve_public_addresses(ns, port=53)
        except UnsafeAddressError:
            ctx.debug(f"AXFR skipped: {ns} does not resolve to a public address")
            continue

        for ns_ip in ns_addresses:
            try:
                zone = dns.zone.from_xfr(
                    dns.query.xfr(ns_ip, ctx.target, timeout=10, lifetime=20)
                )
            except Exception:
                ctx.debug(f"AXFR refused by {ns} (expected)")
                continue

            leaking.append(ns)
            ctx.warn(f"Zone transfer succeeded against {ns} — the full DNS zone is exposed")
            for name in zone.nodes:
                fqdn = normalise_host(
                    f"{name}.{ctx.target}" if str(name) != "@" else ctx.target
                )
                if fqdn:
                    names.add(fqdn)
            # One successful transfer per nameserver is enough to leak the zone.
            break
    return names, leaking


# --- Bruteforce -------------------------------------------------------------


async def _bruteforce(
    ctx: ScanContext, candidates: list[str], wildcard_ips: set[str]
) -> dict[str, list[str]]:
    """Resolve candidates concurrently, dropping wildcard-only answers."""
    resolver = _resolver()
    semaphore = asyncio.Semaphore(_DNS_CONCURRENCY)
    live: dict[str, list[str]] = {}
    checked = 0

    async def probe(hostname: str) -> None:
        nonlocal checked
        async with semaphore:
            addresses = await _resolve_a(hostname, resolver)
            checked += 1
            if checked % 250 == 0:
                ctx.debug(f"Resolved {checked}/{len(candidates)} candidates")
            if not addresses:
                return
            # A host whose only addresses are the wildcard's is not real.
            if wildcard_ips and set(addresses).issubset(wildcard_ips):
                return
            live[hostname] = addresses

    await asyncio.gather(*(probe(h) for h in candidates))
    return live


# --- Persistence ------------------------------------------------------------


def _persist(ctx: ScanContext, hosts: dict[str, list[str]]) -> tuple[int, int]:
    """Upsert discovered hosts. Returns (new, updated)."""
    now = datetime.now(timezone.utc)
    new_count = 0
    updated_count = 0

    with session_scope() as session:
        for hostname, addresses in sorted(hosts.items()):
            public = [a for a in addresses if not is_private_address(a)]
            ip = (public or addresses or [None])[0]

            existing = session.scalar(
                select(Asset).where(Asset.org_id == ctx.org_id, Asset.hostname == hostname)
            )
            if existing is None:
                session.add(
                    Asset(
                        org_id=ctx.org_id,
                        hostname=hostname,
                        ip=ip,
                        status=AssetStatus.NEW,
                        discovery_source=STAGE,
                        first_seen=now,
                        last_scanned=now,
                    )
                )
                new_count += 1
                ctx.emit_result("asset_discovered", {"hostname": hostname, "ip": ip, "new": True})
            else:
                if ip and existing.ip != ip:
                    existing.ip = ip
                    # Address change is meaningful; change_detector picks it up.
                    existing.status = AssetStatus.CHANGED
                existing.last_scanned = now
                updated_count += 1

    return new_count, updated_count


def _record_axfr_finding(ctx: ScanContext, nameservers: list[str]) -> None:
    """Store the open-zone-transfer finding against the apex asset."""
    if not nameservers:
        return
    now = datetime.now(timezone.utc)
    with session_scope() as session:
        asset = session.scalar(
            select(Asset).where(Asset.org_id == ctx.org_id, Asset.hostname == ctx.target)
        )
        asset_id = asset.id if asset else None
        title = f"DNS zone transfer (AXFR) permitted on {ctx.target}"
        fingerprint = Finding.build_fingerprint(asset_id=asset_id, title=title)

        stmt = (
            pg_insert(Finding)
            .values(
                id=uuid.uuid4(),
                org_id=ctx.org_id,
                asset_id=asset_id,
                scan_id=ctx.scan_id,
                title=title,
                severity=Severity.MEDIUM,
                description=(
                    "The authoritative nameserver(s) "
                    f"{', '.join(nameservers)} answered an unauthenticated AXFR "
                    "request, disclosing every record in the zone. This hands an "
                    "attacker a complete map of internal and external hostnames "
                    "without any bruteforcing."
                ),
                remediation=(
                    "Restrict AXFR to your secondary nameservers with an "
                    "allow-transfer ACL (BIND) or the equivalent on your DNS "
                    "provider, and prefer TSIG-authenticated transfers."
                ),
                source=STAGE,
                fingerprint=fingerprint,
                evidence={"nameservers": nameservers},
                references=["https://cwe.mitre.org/data/definitions/200.html"],
                first_seen=now,
                last_seen=now,
            )
            .on_conflict_do_update(
                index_elements=[Finding.org_id, Finding.fingerprint],
                set_={"last_seen": now, "scan_id": ctx.scan_id},
            )
        )
        session.execute(stmt)
    ctx.bump_counters(findings=1)


# --- Task -------------------------------------------------------------------


@shared_task(
    name="workers.subdomain_enum.run",
    bind=True,
    max_retries=2,
    default_retry_delay=30,
    soft_time_limit=900,
)
def run(self, ctx_data: dict[str, Any]) -> dict[str, Any]:
    """Enumerate subdomains and record them as assets.

    Returns the hostnames found so downstream stages can pick them up.
    """
    ctx = ScanContext.load(**ctx_data).for_stage(STAGE)
    ctx.set_stage(STAGE, progress=10)
    ctx.log(f"Starting subdomain enumeration for {ctx.target}")

    allowed = ctx.allowed_domains()
    candidates: set[str] = {ctx.target}

    # --- Passive: CT logs ---
    ct_names = _fetch_crtsh(ctx)
    if ct_names:
        ctx.log(f"Certificate transparency returned {len(ct_names)} unique names")
        candidates |= ct_names

    # --- Zone transfer ---
    leaking: list[str] = []
    if not ctx.passive_only:
        axfr_names, leaking = _try_zone_transfer(ctx)
        if axfr_names:
            ctx.log(f"Zone transfer disclosed {len(axfr_names)} records")
            candidates |= axfr_names

    # --- Bruteforce ---
    if not ctx.passive_only:
        wordlist_candidates = {f"{word}.{ctx.target}" for word in SUBDOMAIN_WORDLIST}
        ctx.log(f"Bruteforcing {len(wordlist_candidates)} common subdomain labels")
        candidates |= wordlist_candidates
    else:
        ctx.log("Passive mode: skipping DNS bruteforce and zone transfer")

    # Scope filter: never store or touch a host outside the verified domains.
    in_scope_candidates = sorted(
        h for h in candidates if h and in_scope(h, allowed or [ctx.target])
    )
    dropped = len(candidates) - len(in_scope_candidates)
    if dropped:
        ctx.debug(f"Dropped {dropped} candidates outside the organisation's scope")

    max_subdomains = int(ctx.option("max_subdomains", 500))
    if len(in_scope_candidates) > max_subdomains:
        ctx.warn(
            f"{len(in_scope_candidates)} candidates exceeds the configured limit of "
            f"{max_subdomains}; truncating"
        )
        in_scope_candidates = in_scope_candidates[:max_subdomains]

    if ctx.is_cancelled():
        ctx.log("Scan cancelled before resolution")
        return {**ctx.to_dict(), "hosts": []}

    async def _resolve_all() -> dict[str, list[str]]:
        resolver = _resolver()
        wildcard_ips = (
            set() if ctx.option("include_wildcards") else await _detect_wildcard(ctx.target, resolver)
        )
        if wildcard_ips:
            ctx.warn(
                f"Wildcard DNS detected on {ctx.target} ({', '.join(sorted(wildcard_ips))}); "
                "filtering catch-all responses"
            )
        return await _bruteforce(ctx, in_scope_candidates, wildcard_ips)

    live_hosts = run_async(_resolve_all())
    ctx.log(f"{len(live_hosts)} of {len(in_scope_candidates)} candidates resolve")

    new_count, updated_count = _persist(ctx, live_hosts)
    ctx.bump_counters(assets=new_count)
    ctx.log(f"Inventory updated: {new_count} new host(s), {updated_count} already known")

    if leaking:
        _record_axfr_finding(ctx, leaking)

    return {
        **ctx.to_dict(),
        "hosts": sorted(live_hosts.keys()),
        "new_hosts": new_count,
    }
