"""Change detection.

Diffs the estate against the baseline snapshot the orchestrator captured before
the scan started (Redis key ``scan:{scan_id}:baseline``), and reports what
moved: new hosts, hosts that disappeared, ports opened or closed, technology
versions that changed.

New exposure is the signal that matters most in ASM — a port that opened
yesterday is far more interesting than one that has been open for a year — so
newly-opened sensitive ports are raised as findings in their own right.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

import redis
from celery import shared_task
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from core.events import sync_redis
from core.scoring import port_exposure_severity
from db.database import session_scope
from models import Asset, AssetStatus, Finding, Severity
from workers.context import ScanContext

STAGE = "change_detector"

_BASELINE_TTL = 60 * 60 * 24 * 7  # a week is plenty; scans finish in minutes


def baseline_key(scan_id: uuid.UUID | str) -> str:
    return f"scan:{scan_id}:baseline"


def capture_baseline(org_id: uuid.UUID, scan_id: uuid.UUID) -> int:
    """Snapshot the org's current asset state. Called by the orchestrator
    before any scanning stage mutates the inventory."""
    with session_scope() as session:
        assets = list(session.scalars(select(Asset).where(Asset.org_id == org_id)))
        snapshot = {
            a.hostname: {
                "ip": a.ip,
                "ports": sorted(
                    p["port"] for p in (a.ports or []) if p.get("state") == "open" and "port" in p
                ),
                "tech": {
                    (t.get("name") or ""): t.get("version")
                    for t in (a.tech_stack or [])
                    if t.get("name")
                },
                "risk_score": a.risk_score,
            }
            for a in assets
        }

    try:
        sync_redis().setex(baseline_key(scan_id), _BASELINE_TTL, json.dumps(snapshot))
    except redis.RedisError:
        # Without a baseline the module reports everything as new, which is the
        # correct behaviour for a first-ever scan anyway.
        return 0
    return len(snapshot)


def _load_baseline(scan_id: uuid.UUID) -> dict[str, dict[str, Any]] | None:
    try:
        raw = sync_redis().get(baseline_key(scan_id))
    except redis.RedisError:
        return None
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def _record_new_exposure(
    ctx: ScanContext, asset_id: uuid.UUID, hostname: str, ports: list[int]
) -> int:
    """Raise a finding for each newly-opened sensitive port."""
    now = datetime.now(timezone.utc)
    count = 0

    with session_scope() as session:
        for port in ports:
            severity = port_exposure_severity(port)
            # Only escalate ports that actually matter; a new port 8080 on a web
            # host is noise.
            if severity in {Severity.INFO, Severity.LOW}:
                continue

            title = f"New exposure: port {port} opened on {hostname}"
            stmt = (
                pg_insert(Finding)
                .values(
                    id=uuid.uuid4(),
                    org_id=ctx.org_id,
                    asset_id=asset_id,
                    scan_id=ctx.scan_id,
                    title=title,
                    severity=severity,
                    description=(
                        f"Port {port} on {hostname} was not open during the previous "
                        "scan and is now accepting connections. Unplanned exposure "
                        "often means a firewall change, a new deployment, or a "
                        "service that was never meant to be public."
                    ),
                    remediation=(
                        "Confirm this exposure was intentional. If not, close the port "
                        "at the perimeter and review the change that introduced it."
                    ),
                    source=STAGE,
                    fingerprint=Finding.build_fingerprint(
                        asset_id=asset_id, title=title, port=port
                    ),
                    evidence={"hostname": hostname, "port": port, "change": "port_opened"},
                    first_seen=now,
                    last_seen=now,
                )
                .on_conflict_do_update(
                    index_elements=[Finding.org_id, Finding.fingerprint],
                    set_={"last_seen": now, "scan_id": ctx.scan_id},
                )
            )
            session.execute(stmt)
            count += 1

    return count


@shared_task(
    name="workers.change_detector.run",
    bind=True,
    max_retries=1,
    default_retry_delay=60,
    soft_time_limit=600,
)
def run(self, payload: dict[str, Any]) -> dict[str, Any]:
    ctx = ScanContext.load(
        scan_id=payload["scan_id"],
        org_id=payload["org_id"],
        target=payload["target"],
        config=payload.get("config") or {},
    ).for_stage(STAGE)

    ctx.set_stage(STAGE, progress=92)

    baseline = _load_baseline(ctx.scan_id)
    if baseline is None:
        ctx.log("No baseline available — treating this as the first scan of the estate")
        baseline = {}

    now = datetime.now(timezone.utc)
    scanned_hosts: set[str] = set(payload.get("hosts") or [])

    with session_scope() as session:
        current_assets = list(session.scalars(select(Asset).where(Asset.org_id == ctx.org_id)))
        current = {
            a.hostname: {
                "id": a.id,
                "ip": a.ip,
                "ports": sorted(
                    p["port"] for p in (a.ports or []) if p.get("state") == "open" and "port" in p
                ),
                "tech": {
                    (t.get("name") or ""): t.get("version")
                    for t in (a.tech_stack or [])
                    if t.get("name")
                },
            }
            for a in current_assets
        }

    changes: list[dict[str, Any]] = []
    new_hosts = sorted(set(current) - set(baseline))
    missing_hosts = sorted(set(baseline) - set(current))

    for hostname in new_hosts:
        changes.append({"type": "host_added", "hostname": hostname})
    for hostname in missing_hosts:
        changes.append({"type": "host_removed", "hostname": hostname})

    exposure_findings = 0
    changed_assets: list[uuid.UUID] = []

    for hostname, state in current.items():
        before = baseline.get(hostname)
        if before is None:
            # Brand-new host: its open ports are all new exposure, but the port
            # scanner has already reported them, so do not double-report here.
            continue

        # Only diff hosts this scan actually looked at — otherwise an untouched
        # host would appear to have "lost" every port.
        if scanned_hosts and hostname not in scanned_hosts:
            continue

        host_changed = False

        opened = sorted(set(state["ports"]) - set(before.get("ports") or []))
        closed = sorted(set(before.get("ports") or []) - set(state["ports"]))
        if opened:
            changes.append({"type": "ports_opened", "hostname": hostname, "ports": opened})
            ctx.log(
                f"{hostname}: newly opened port(s) {', '.join(map(str, opened))}",
                level="warning",
            )
            exposure_findings += _record_new_exposure(ctx, state["id"], hostname, opened)
            host_changed = True
        if closed:
            changes.append({"type": "ports_closed", "hostname": hostname, "ports": closed})
            ctx.log(f"{hostname}: port(s) {', '.join(map(str, closed))} no longer respond")
            host_changed = True

        before_ip = before.get("ip")
        if before_ip and state["ip"] and before_ip != state["ip"]:
            changes.append(
                {
                    "type": "ip_changed",
                    "hostname": hostname,
                    "from": before_ip,
                    "to": state["ip"],
                }
            )
            ctx.log(f"{hostname}: address changed {before_ip} -> {state['ip']}")
            host_changed = True

        before_tech = before.get("tech") or {}
        for name, version in state["tech"].items():
            if name not in before_tech:
                changes.append(
                    {"type": "tech_added", "hostname": hostname, "name": name, "version": version}
                )
                host_changed = True
            elif version and before_tech[name] and version != before_tech[name]:
                changes.append(
                    {
                        "type": "tech_version_changed",
                        "hostname": hostname,
                        "name": name,
                        "from": before_tech[name],
                        "to": version,
                    }
                )
                ctx.log(
                    f"{hostname}: {name} {before_tech[name]} -> {version}"
                )
                host_changed = True

        if host_changed:
            changed_assets.append(state["id"])

    # Reflect the diff in asset status so the UI can highlight movement.
    with session_scope() as session:
        for asset_id in changed_assets:
            asset = session.get(Asset, asset_id)
            if asset is not None and asset.status != AssetStatus.NEW:
                asset.status = AssetStatus.CHANGED

        for hostname in missing_hosts:
            asset = session.scalar(
                select(Asset).where(Asset.org_id == ctx.org_id, Asset.hostname == hostname)
            )
            if asset is not None:
                # Do not delete: an asset that stops resolving may come back, and
                # its finding history is worth keeping.
                asset.status = AssetStatus.INACTIVE

        # Hosts seen in this scan settle from "new" into "active".
        for hostname in scanned_hosts:
            asset = session.scalar(
                select(Asset).where(Asset.org_id == ctx.org_id, Asset.hostname == hostname)
            )
            if asset is not None and asset.status == AssetStatus.NEW and hostname not in new_hosts:
                asset.status = AssetStatus.ACTIVE
                asset.last_scanned = now

    if exposure_findings:
        ctx.bump_counters(findings=exposure_findings)

    if changes:
        ctx.emit_result("changes", changes)
        ctx.log(
            f"Change detection complete: {len(changes)} change(s) — "
            f"{len(new_hosts)} host(s) added, {len(missing_hosts)} no longer resolving, "
            f"{exposure_findings} new exposure finding(s)"
        )
    else:
        ctx.log("Change detection complete: no changes since the previous scan")

    try:
        sync_redis().delete(baseline_key(ctx.scan_id))
    except redis.RedisError:
        pass

    return {**payload, "changes": changes}
