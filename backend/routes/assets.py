"""Asset inventory."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import desc, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from core.deps import AnalystDep, CurrentUserDep, DbDep, PaginationDep
from core.scoring import OutOfScopeError, assert_in_scope, port_exposure_severity
from models import Asset, AssetStatus, Finding, FindingStatus, Organisation
from models.base import Severity
from schemas.asset import (
    AssetCreate,
    AssetOut,
    AssetStatsOut,
    AssetSummary,
    AssetUpdate,
    GraphLink,
    GraphNode,
    GraphOut,
)
from schemas.common import Message, PaginatedResponse
from schemas.finding import FindingOut

router = APIRouter(prefix="/api/assets", tags=["assets"])

# "Still your problem" — the three statuses that mean nobody has decided this is
# handled. Remediated, false-positive and accepted-risk findings are excluded
# from every count the UI shows, so a triaged estate stops looking on fire.
_OPEN_FINDING_STATUSES = (FindingStatus.OPEN, FindingStatus.TRIAGED, FindingStatus.CONFIRMED)

# Severity → a point on the same 0-100 axis assets are scored on. The values sit
# mid-band against riskBand() in frontend/src/lib/format.ts (80 / 60 / 35), so a
# port node lands in the colour its severity name implies. Ports have no CVSS
# and no scored history — this is the only way to give them a comparable number.
_PORT_SEVERITY_SCORE: dict[Severity, float] = {
    Severity.CRITICAL: 90.0,
    Severity.HIGH: 70.0,
    Severity.MEDIUM: 45.0,
    Severity.LOW: 15.0,
    Severity.INFO: 0.0,
}


async def _get_asset_or_404(asset_id: uuid.UUID, org_id: uuid.UUID, db: AsyncSession) -> Asset:
    asset = await db.scalar(select(Asset).where(Asset.id == asset_id, Asset.org_id == org_id))
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    return asset


@router.get("", response_model=PaginatedResponse[AssetSummary], summary="List assets")
async def list_assets(
    current: CurrentUserDep,
    db: DbDep,
    page: PaginationDep,
    status_filter: AssetStatus | None = Query(default=None, alias="status"),
    hostname: str | None = Query(default=None, description="Substring match"),
    min_risk: float | None = Query(default=None, ge=0, le=100),
    port: int | None = Query(default=None, ge=1, le=65535, description="Has this port open"),
    technology: str | None = Query(default=None, description="Runs this technology"),
    sort: str = Query(default="risk", pattern="^(risk|hostname|last_scanned|created)$"),
) -> PaginatedResponse[AssetSummary]:
    conditions = [Asset.org_id == current.org_id]
    if status_filter is not None:
        conditions.append(Asset.status == status_filter)
    if hostname:
        conditions.append(Asset.hostname.ilike(f"%{hostname}%"))
    if min_risk is not None:
        conditions.append(Asset.risk_score >= min_risk)
    if port is not None:
        # JSONB containment — hits ix_assets_ports_gin.
        conditions.append(Asset.ports.contains([{"port": port, "state": "open"}]))
    if technology:
        conditions.append(Asset.tech_stack.contains([{"name": technology}]))

    order = {
        "risk": desc(Asset.risk_score),
        "hostname": Asset.hostname,
        "last_scanned": desc(Asset.last_scanned),
        "created": desc(Asset.created_at),
    }[sort]

    total = await db.scalar(select(func.count(Asset.id)).where(*conditions)) or 0

    # Open-finding count per asset, folded into the list query.
    finding_counts = (
        select(Finding.asset_id, func.count(Finding.id).label("cnt"))
        .where(
            Finding.org_id == current.org_id,
            Finding.status.in_(_OPEN_FINDING_STATUSES),
        )
        .group_by(Finding.asset_id)
        .subquery()
    )

    rows = await db.execute(
        select(Asset, func.coalesce(finding_counts.c.cnt, 0))
        .outerjoin(finding_counts, finding_counts.c.asset_id == Asset.id)
        .where(*conditions)
        .order_by(order)
        .limit(page.limit)
        .offset(page.offset)
    )

    items: list[AssetSummary] = []
    for asset, finding_count in rows:
        summary = AssetSummary.model_validate(asset)
        summary.open_port_count = len(asset.open_ports)
        summary.finding_count = finding_count
        items.append(summary)

    return PaginatedResponse[AssetSummary](
        items=items, total=total, limit=page.limit, offset=page.offset
    )


@router.post(
    "",
    response_model=AssetOut,
    status_code=status.HTTP_201_CREATED,
    summary="Add an asset manually",
)
async def create_asset(body: AssetCreate, current: AnalystDep, db: DbDep) -> Asset:
    org = await db.scalar(select(Organisation).where(Organisation.id == current.org_id))
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organisation not found")

    try:
        hostname = assert_in_scope(
            body.hostname, org.all_domains, allow_arbitrary=settings.allow_arbitrary_targets
        )
    except OutOfScopeError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc

    now = datetime.now(timezone.utc)
    asset = Asset(
        org_id=current.org_id,
        hostname=hostname,
        ip=body.ip,
        notes=body.notes,
        status=AssetStatus.NEW,
        discovery_source="manual",
        first_seen=now,
    )
    db.add(asset)
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"{hostname} is already in your inventory",
        ) from exc

    await db.refresh(asset)
    return asset


@router.get("/stats", response_model=AssetStatsOut, summary="Inventory summary")
async def asset_stats(current: CurrentUserDep, db: DbDep) -> AssetStatsOut:
    since = datetime.now(timezone.utc) - timedelta(days=7)

    total = await db.scalar(select(func.count(Asset.id)).where(Asset.org_id == current.org_id)) or 0

    rows = await db.execute(
        select(Asset.status, func.count(Asset.id))
        .where(Asset.org_id == current.org_id)
        .group_by(Asset.status)
    )
    by_status = {s.value: 0 for s in AssetStatus}
    for asset_status, count in rows:
        by_status[asset_status.value] = count

    new_7d = await db.scalar(
        select(func.count(Asset.id)).where(
            Asset.org_id == current.org_id, Asset.first_seen >= since
        )
    ) or 0

    top = await db.scalars(
        select(Asset)
        .where(Asset.org_id == current.org_id)
        .order_by(desc(Asset.risk_score))
        .limit(10)
    )
    highest = []
    for asset in top:
        summary = AssetSummary.model_validate(asset)
        summary.open_port_count = len(asset.open_ports)
        highest.append(summary)

    return AssetStatsOut(
        total=total,
        by_status=by_status,
        highest_risk=highest,
        newly_discovered_7d=new_7d,
    )


# Declared above /{asset_id} deliberately. FastAPI matches routes in
# declaration order, so with this below it the literal path "graph" would be
# fed to the asset_id: uuid.UUID parameter and every request would 422.
@router.get("/graph", response_model=GraphOut, summary="Blast radius graph")
async def asset_graph(
    current: CurrentUserDep,
    db: DbDep,
    include_ports: bool = Query(
        default=True, description="Include a node per open port"
    ),
    max_assets: int = Query(
        default=150,
        ge=1,
        le=500,
        description="Cap on subdomain nodes, highest risk first",
    ),
) -> GraphOut:
    """Domain → subdomains → IPs → ports, as a graph.

    The structure is not just decoration. Assets are joined to *shared* IP
    nodes, so when eight subdomains resolve to one host the graph shows one
    node with eight edges — which is the actual blast radius of compromising
    that host, and the thing a flat asset table cannot show you.

    Everything is scoped to ``current.org_id``. There is no cross-org read path
    here even by asset id, because ids are never accepted as input.
    """
    org = await db.scalar(select(Organisation).where(Organisation.id == current.org_id))
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organisation not found")

    total_assets = (
        await db.scalar(select(func.count(Asset.id)).where(Asset.org_id == current.org_id)) or 0
    )

    # Highest risk first, so a truncated graph keeps what matters.
    assets = list(
        await db.scalars(
            select(Asset)
            .where(Asset.org_id == current.org_id)
            .order_by(desc(Asset.risk_score), Asset.hostname)
            .limit(max_assets)
        )
    )

    # Open findings per asset, in one grouped query rather than per node.
    counts_rows = await db.execute(
        select(Finding.asset_id, func.count(Finding.id))
        .where(
            Finding.org_id == current.org_id,
            Finding.status.in_(_OPEN_FINDING_STATUSES),
        )
        .group_by(Finding.asset_id)
    )
    finding_counts = {asset_id: count for asset_id, count in counts_rows if asset_id}

    nodes: list[GraphNode] = []
    links: list[GraphLink] = []
    seen_links: set[tuple[str, str]] = set()

    def add_link(source: str, target: str) -> None:
        # Deduped: two assets on one IP would otherwise emit the same ip→port
        # edge twice, and D3's force simulation treats duplicate links as
        # additional springs, visibly collapsing that pair together.
        key = (source, target)
        if key not in seen_links:
            seen_links.add(key)
            links.append(GraphLink(source=source, target=target))

    # --- domain roots ------------------------------------------------------
    # No `or [org.domain]` fallback: an org with no verified domains has no
    # authorised roots, and rendering its unverified primary domain as a graph
    # root would show a scope it does not actually have.
    domains = org.all_domains
    for domain in domains:
        nodes.append(
            GraphNode(id=f"domain:{domain}", label=domain, kind="domain", risk_score=0.0)
        )

    def parent_domain(hostname: str) -> str | None:
        """Longest verified domain this hostname sits under, or None.

        Longest wins so that a host under both "acme.test" and the more
        specific "eu.acme.test" attaches to the latter, which is what someone
        looking at the map expects to see.

        None means the asset is covered by no verified domain — possible when a
        lab ran with ALLOW_ARBITRARY_TARGETS, or when a domain was revoked after
        the asset was discovered. The node then renders without a domain root
        instead of crashing the whole graph.
        """
        host = hostname.lower().strip(".")
        best: str | None = None
        for domain in domains:
            d = domain.lower().strip(".")
            if (host == d or host.endswith("." + d)) and (best is None or len(d) > len(best)):
                best = d
        return best

    # --- subdomain + ip nodes ---------------------------------------------
    ip_children: dict[str, list[Asset]] = {}

    for asset in assets:
        node_id = f"asset:{asset.id}"
        open_ports = asset.open_ports
        nodes.append(
            GraphNode(
                id=node_id,
                label=asset.hostname,
                kind="subdomain",
                risk_score=asset.risk_score,
                asset_id=asset.id,
                finding_count=finding_counts.get(asset.id, 0),
                open_port_count=len(open_ports),
            )
        )
        parent = parent_domain(asset.hostname)
        if parent is not None:
            add_link(f"domain:{parent}", node_id)

        if asset.ip:
            ip_children.setdefault(asset.ip, []).append(asset)

    for ip, children in ip_children.items():
        ip_id = f"ip:{ip}"
        nodes.append(
            GraphNode(
                id=ip_id,
                label=ip,
                kind="ip",
                # The worst thing reachable through this host. An IP is exactly
                # as dangerous as the most exposed name pointing at it.
                risk_score=max(a.risk_score for a in children),
                shared_by=len(children),
                finding_count=sum(finding_counts.get(a.id, 0) for a in children),
            )
        )
        for asset in children:
            add_link(f"asset:{asset.id}", ip_id)

    # --- port nodes --------------------------------------------------------
    if include_ports:
        # Keyed by (ip, port) so a port on a shared host is one node, matching
        # reality: there is one sshd on that box, not one per DNS name.
        port_nodes: dict[str, dict[str, Any]] = {}
        for asset in assets:
            anchor = f"ip:{asset.ip}" if asset.ip else f"asset:{asset.id}"
            for entry in asset.ports or []:
                if entry.get("state") != "open" or entry.get("port") is None:
                    continue
                port = int(entry["port"])
                port_id = f"port:{asset.ip or asset.id}:{port}"
                existing = port_nodes.get(port_id)
                if existing is None:
                    port_nodes[port_id] = {
                        "port": port,
                        "service": entry.get("service"),
                        "anchor": anchor,
                    }
                elif not existing["service"] and entry.get("service"):
                    existing["service"] = entry["service"]

        for port_id, meta in port_nodes.items():
            nodes.append(
                GraphNode(
                    id=port_id,
                    label=str(meta["port"]),
                    kind="port",
                    # Exposure severity mapped onto the same 0-100 scale the
                    # other nodes use, so one riskBand() call colours them all.
                    risk_score=_PORT_SEVERITY_SCORE[port_exposure_severity(meta["port"])],
                    service=meta["service"],
                )
            )
            add_link(meta["anchor"], port_id)

    # --- roll risk up to the domain roots ----------------------------------
    # Done after the fact rather than in the loop above because a root's risk
    # is defined by its children, and they are not all known until now.
    child_risk: dict[str, float] = {}
    for asset in assets:
        key = f"domain:{parent_domain(asset.hostname)}"
        child_risk[key] = max(child_risk.get(key, 0.0), asset.risk_score)
    for node in nodes:
        if node.kind == "domain":
            node.risk_score = child_risk.get(node.id, 0.0)

    truncated = total_assets > len(assets)
    return GraphOut(
        nodes=nodes,
        links=links,
        total_assets=total_assets,
        truncated=truncated,
        truncated_reason=(
            f"Showing the {len(assets)} highest-risk assets of {total_assets}. "
            f"A force-directed graph stops being readable — and stops being "
            f"interactive — well before an estate this size."
            if truncated
            else None
        ),
    )


@router.get("/{asset_id}", response_model=AssetOut, summary="Get one asset")
async def get_asset(asset_id: uuid.UUID, current: CurrentUserDep, db: DbDep) -> Asset:
    return await _get_asset_or_404(asset_id, current.org_id, db)


@router.get(
    "/{asset_id}/findings",
    response_model=list[FindingOut],
    summary="Findings on one asset",
)
async def asset_findings(
    asset_id: uuid.UUID, current: CurrentUserDep, db: DbDep
) -> list[FindingOut]:
    asset = await _get_asset_or_404(asset_id, current.org_id, db)
    rows = await db.scalars(
        select(Finding)
        .where(Finding.asset_id == asset.id, Finding.org_id == current.org_id)
        .order_by(desc(Finding.cvss_score).nullslast(), desc(Finding.created_at))
    )
    out = []
    for finding in rows:
        item = FindingOut.model_validate(finding)
        item.asset_hostname = asset.hostname
        out.append(item)
    return out


@router.patch("/{asset_id}", response_model=AssetOut, summary="Update an asset")
async def update_asset(
    asset_id: uuid.UUID, body: AssetUpdate, current: AnalystDep, db: DbDep
) -> Asset:
    asset = await _get_asset_or_404(asset_id, current.org_id, db)
    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(asset, field, value)
    await db.commit()
    await db.refresh(asset)
    return asset


@router.delete("/{asset_id}", response_model=Message, summary="Delete an asset")
async def delete_asset(asset_id: uuid.UUID, current: AnalystDep, db: DbDep) -> Message:
    asset = await _get_asset_or_404(asset_id, current.org_id, db)
    hostname = asset.hostname
    await db.delete(asset)
    await db.commit()
    return Message(detail=f"{hostname} removed from inventory")
