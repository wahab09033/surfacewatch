"""TCP port scanning.

Uses asyncio TCP connect scans rather than shelling out to nmap: no root
required, no subprocess parsing, and the concurrency is bounded per host so a
scan cannot turn into an accidental flood. Banners are grabbed opportunistically
for service identification.
"""

from __future__ import annotations

import asyncio
import ipaddress
import uuid
from datetime import datetime, timezone
from typing import Any

from celery import shared_task
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from core.scoring import (
    UnsafeAddressError,
    port_exposure_severity,
    resolve_public_addresses,
    score_asset,
)
from db.database import session_scope
from models import Asset, Finding
from workers.context import ScanContext, run_async
from workers.wordlists import COMMON_SERVICES, resolve_port_profile

STAGE = "port_scanner"

# Ports where an unauthenticated service is a serious finding in its own right.
_SENSITIVE_SERVICES: dict[int, tuple[str, str]] = {
    23: (
        "Telnet exposed to the internet",
        "Telnet transmits credentials in cleartext. Disable it and use SSH.",
    ),
    21: (
        "FTP exposed to the internet",
        "Plain FTP sends credentials and data unencrypted. Move to SFTP or FTPS.",
    ),
    445: (
        "SMB exposed to the internet",
        "SMB should never be internet-facing. Block 445 at the perimeter and use a VPN.",
    ),
    3389: (
        "RDP exposed to the internet",
        "Put RDP behind a VPN or gateway and enforce MFA; it is a primary ransomware entry point.",
    ),
    6379: (
        "Redis exposed to the internet",
        "Redis has no authentication by default. Bind to localhost, set requirepass, and firewall 6379.",
    ),
    11211: (
        "Memcached exposed to the internet",
        "Memcached is unauthenticated and amplifies UDP reflection attacks. Bind to localhost.",
    ),
    9200: (
        "Elasticsearch exposed to the internet",
        "Enable authentication (X-Pack/OpenSearch security) and restrict 9200 to internal networks.",
    ),
    27017: (
        "MongoDB exposed to the internet",
        "Enable authentication and bind MongoDB to a private interface.",
    ),
    2375: (
        "Unencrypted Docker API exposed",
        "An open Docker socket is root on the host. Disable TCP exposure or require mTLS.",
    ),
    10250: (
        "Kubelet API exposed",
        "Restrict the kubelet read/write port and require authentication and authorisation.",
    ),
    5432: (
        "PostgreSQL exposed to the internet",
        "Restrict 5432 to application subnets and require TLS with strong authentication.",
    ),
    3306: (
        "MySQL exposed to the internet",
        "Restrict 3306 to application subnets; do not expose the database publicly.",
    ),
    5900: (
        "VNC exposed to the internet",
        "VNC authentication is weak. Tunnel it over SSH or a VPN.",
    ),
}


async def _probe_port(
    host: str, port: int, timeout: float, semaphore: asyncio.Semaphore
) -> dict[str, Any] | None:
    """Connect to one port; on success try a short banner read.

    ``host`` must already be a validated public IP — see ``_scan_host``. Passing
    a name here would hand resolution back to the OS and reopen the rebinding
    window this module closes.
    """
    async with semaphore:
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None

        banner = ""
        try:
            # Many services (SSH, SMTP, FTP) speak first. Give them a moment;
            # for silent ones the timeout is the cost of one short wait.
            raw = await asyncio.wait_for(reader.read(256), timeout=1.5)
            banner = raw.decode("utf-8", errors="replace").strip()
        except (asyncio.TimeoutError, OSError):
            pass
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except (OSError, asyncio.TimeoutError):
                    pass

        return {
            "port": port,
            "protocol": "tcp",
            "state": "open",
            "service": COMMON_SERVICES.get(port, "unknown"),
            "banner": banner[:500] or None,
        }


async def _probe_address(
    address: str, ports: list[int], timeout: float, concurrency: int
) -> list[dict[str, Any]]:
    """Fan out probes across one already-validated IP address."""
    semaphore = asyncio.Semaphore(concurrency)
    results = await asyncio.gather(
        *(_probe_port(address, port, timeout, semaphore) for port in ports)
    )
    return sorted((r for r in results if r), key=lambda r: r["port"])


async def _scan_host(
    ctx: ScanContext, host: str, ports: list[int], timeout: float, concurrency: int
) -> list[dict[str, Any]]:
    """Resolve ``host``, refuse it if it points inward, then scan the address.

    Raises ``UnsafeAddressError`` when ``host`` resolves into reserved space;
    the caller logs it and moves on, so a poisoned record only costs us that
    one host. ``host`` may be a name or a literal — either way it is resolved
    *here, once*, and the probes connect to the validated IP rather than to the
    name, which would hand resolution back to the OS at connect time.
    """
    addresses = resolve_public_addresses(host, port=ports[0] if ports else 0)
    address = next(
        (a for a in addresses if ipaddress.ip_address(a).version == 4), addresses[0]
    )
    return await _probe_address(address, ports, timeout, concurrency)


def _record_port_findings(
    ctx: ScanContext, asset_id: uuid.UUID, hostname: str, ports: list[dict[str, Any]]
) -> int:
    """Raise findings for sensitive exposed services."""
    now = datetime.now(timezone.utc)
    recorded = 0

    with session_scope() as session:
        for entry in ports:
            port = entry["port"]
            template = _SENSITIVE_SERVICES.get(port)
            if template is None:
                continue

            title, remediation = template
            severity = port_exposure_severity(port)
            fingerprint = Finding.build_fingerprint(
                asset_id=asset_id, title=title, port=port
            )
            description = (
                f"{hostname} accepts TCP connections on port {port} "
                f"({entry.get('service') or 'unknown service'}) from the public internet."
            )
            if entry.get("banner"):
                description += f" The service returned the banner: {entry['banner'][:200]!r}."

            stmt = (
                pg_insert(Finding)
                .values(
                    id=uuid.uuid4(),
                    org_id=ctx.org_id,
                    asset_id=asset_id,
                    scan_id=ctx.scan_id,
                    title=f"{title} ({hostname}:{port})",
                    severity=severity,
                    description=description,
                    remediation=remediation,
                    source=STAGE,
                    fingerprint=fingerprint,
                    evidence={
                        "hostname": hostname,
                        "port": port,
                        "service": entry.get("service"),
                        "banner": entry.get("banner"),
                    },
                    first_seen=now,
                    last_seen=now,
                )
                .on_conflict_do_update(
                    index_elements=[Finding.org_id, Finding.fingerprint],
                    set_={"last_seen": now, "scan_id": ctx.scan_id, "severity": severity},
                )
            )
            session.execute(stmt)
            recorded += 1
            ctx.emit_result(
                "finding",
                {"hostname": hostname, "port": port, "title": title, "severity": severity.value},
            )

    return recorded


@shared_task(
    name="workers.port_scanner.run",
    bind=True,
    max_retries=1,
    default_retry_delay=60,
    soft_time_limit=1_800,
)
def run(self, payload: dict[str, Any]) -> dict[str, Any]:
    """Port-scan every host discovered so far."""
    hosts: list[str] = payload.get("hosts") or []
    ctx = ScanContext.load(
        scan_id=payload["scan_id"],
        org_id=payload["org_id"],
        target=payload["target"],
        config=payload.get("config") or {},
    ).for_stage(STAGE)

    ctx.set_stage(STAGE, progress=35)

    if ctx.passive_only:
        ctx.log("Passive mode: skipping port scan")
        return {**payload, "scanned_hosts": 0}

    if not hosts:
        hosts = [ctx.target]

    ports = resolve_port_profile(
        ctx.option("port_profile", "top-1000"), ctx.option("ports") or []
    )
    timeout = float(ctx.option("connect_timeout", 2.0))
    concurrency = min(int(ctx.option("rate_limit", 50)), 500)

    ctx.log(
        f"Scanning {len(ports)} ports across {len(hosts)} host(s) "
        f"(timeout {timeout}s, {concurrency} concurrent)"
    )

    total_open = 0
    scanned = 0
    skipped: list[str] = []
    host_results: dict[str, list[dict[str, Any]]] = {}

    for host in hosts:
        if ctx.is_cancelled():
            ctx.log("Scan cancelled; stopping port scan")
            break

        try:
            open_ports = run_async(_scan_host(ctx, host, ports, timeout, concurrency))
        except UnsafeAddressError as exc:
            # A name that passed the scope check at scan-creation time can still
            # resolve somewhere it has no business pointing. Skip the host, keep
            # the scan running, and say so loudly enough to be audited.
            ctx.warn(f"Skipping {host}: {exc}")
            skipped.append(host)
            continue

        scanned += 1
        host_results[host] = open_ports

        if open_ports:
            listing = ", ".join(str(p["port"]) for p in open_ports)
            ctx.log(f"{host}: {len(open_ports)} open port(s) — {listing}")
            ctx.emit_result("ports", {"hostname": host, "ports": open_ports})
        else:
            ctx.debug(f"{host}: no open ports in profile")

        total_open += len(open_ports)

        # Persist per host so results are visible while the scan is still running.
        now = datetime.now(timezone.utc)
        findings_added = 0
        with session_scope() as session:
            asset = session.scalar(
                select(Asset).where(Asset.org_id == ctx.org_id, Asset.hostname == host)
            )
            if asset is None:
                asset = Asset(
                    org_id=ctx.org_id,
                    hostname=host,
                    status="new",
                    discovery_source=STAGE,
                    first_seen=now,
                )
                session.add(asset)
                session.flush()

            asset.ports = open_ports
            asset.last_scanned = now
            asset_id = asset.id

        findings_added = _record_port_findings(ctx, asset_id, host, open_ports)

        # Recompute risk with the new port data and existing findings.
        with session_scope() as session:
            asset = session.get(Asset, asset_id)
            if asset is not None:
                severities = list(
                    session.scalars(
                        select(Finding.severity).where(
                            Finding.asset_id == asset_id, Finding.org_id == ctx.org_id
                        )
                    )
                )
                asset.risk_score = score_asset(
                    findings=severities, open_ports=[p["port"] for p in open_ports]
                )

        if findings_added:
            ctx.bump_counters(findings=findings_added)

    if skipped:
        ctx.warn(
            f"{len(skipped)} host(s) skipped as unsafe to contact: {', '.join(skipped)}"
        )
        # Drop them from the payload so later stages do not try the same names.
        hosts = [h for h in hosts if h not in set(skipped)]

    ctx.log(f"Port scan complete: {total_open} open port(s) across {scanned} host(s)")
    return {**payload, "hosts": hosts, "port_results": host_results, "scanned_hosts": scanned}
