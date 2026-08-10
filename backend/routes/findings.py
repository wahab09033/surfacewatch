"""Findings: triage queue and vulnerability detail."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import case, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from core.deps import AnalystDep, CurrentUserDep, DbDep, PaginationDep
from models import Asset, Finding, FindingStatus, Severity
from schemas.common import Message, PaginatedResponse
from schemas.finding import FindingCreate, FindingOut, FindingStatsOut, FindingUpdate
from services.ai_remediation import SOURCE_ANALYST

router = APIRouter(prefix="/api/findings", tags=["findings"])

_OPEN_STATUSES = [FindingStatus.OPEN, FindingStatus.TRIAGED, FindingStatus.CONFIRMED]

# Ordering for severity sorts — Postgres would otherwise sort the enum
# alphabetically, putting "critical" after "high".
_SEVERITY_ORDER = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


async def _get_finding_or_404(finding_id: uuid.UUID, org_id: uuid.UUID, db: AsyncSession) -> Finding:
    finding = await db.scalar(
        select(Finding).where(Finding.id == finding_id, Finding.org_id == org_id)
    )
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return finding


async def _hostname_for(finding: Finding, org_id: uuid.UUID, db: AsyncSession) -> str | None:
    """The finding's asset hostname, or None if it belongs to another org.

    Scoped to the caller's org rather than looked up by asset_id alone. Every
    write path already checks that a finding's asset belongs to the same
    organisation, but the foreign key points at ``assets.id`` with no composite
    constraint, so the database does not enforce it — and a bare lookup here
    would turn any row that slipped through into a hostname disclosure.
    """
    if not finding.asset_id:
        return None
    return await db.scalar(
        select(Asset.hostname).where(Asset.id == finding.asset_id, Asset.org_id == org_id)
    )


@router.get("", response_model=PaginatedResponse[FindingOut], summary="List findings")
async def list_findings(
    current: CurrentUserDep,
    db: DbDep,
    page: PaginationDep,
    severity: list[Severity] | None = Query(default=None),
    status_filter: list[FindingStatus] | None = Query(default=None, alias="status"),
    asset_id: uuid.UUID | None = Query(default=None),
    scan_id: uuid.UUID | None = Query(default=None),
    cve_id: str | None = Query(default=None),
    search: str | None = Query(default=None, description="Match title or description"),
    open_only: bool = Query(default=False),
    sort: str = Query(default="severity", pattern="^(severity|cvss|created|last_seen)$"),
) -> PaginatedResponse[FindingOut]:
    conditions = [Finding.org_id == current.org_id]
    if severity:
        conditions.append(Finding.severity.in_(severity))
    if status_filter:
        conditions.append(Finding.status.in_(status_filter))
    if open_only:
        conditions.append(Finding.status.in_(_OPEN_STATUSES))
    if asset_id:
        conditions.append(Finding.asset_id == asset_id)
    if scan_id:
        conditions.append(Finding.scan_id == scan_id)
    if cve_id:
        conditions.append(Finding.cve_id == cve_id.upper())
    if search:
        pattern = f"%{search}%"
        conditions.append(Finding.title.ilike(pattern) | Finding.description.ilike(pattern))

    # Rank severity explicitly. Sorting on the enum column would depend on the
    # Postgres type's declaration order, and sorting on cvss_score alone drops
    # score-less findings (exposed services, zone transfers) below trivial
    # scored ones.
    severity_rank = case(_SEVERITY_ORDER, value=Finding.severity, else_=0)
    order = {
        "severity": (
            desc(severity_rank),
            desc(func.coalesce(Finding.cvss_score, 0.0)),
            desc(Finding.created_at),
        ),
        "cvss": (desc(Finding.cvss_score).nullslast(),),
        "created": (desc(Finding.created_at),),
        "last_seen": (desc(Finding.last_seen).nullslast(),),
    }[sort]

    total = await db.scalar(select(func.count(Finding.id)).where(*conditions)) or 0

    rows = await db.execute(
        select(Finding, Asset.hostname)
        # The org predicate belongs on the join, not just on Finding. A
        # finding's asset_id is checked against the caller's org on every write
        # path, but the FK is to assets.id alone — nothing in the schema forbids
        # a row pointing across tenants, and this join would print the other
        # org's hostname if one ever did.
        .outerjoin(Asset, (Asset.id == Finding.asset_id) & (Asset.org_id == current.org_id))
        .where(*conditions)
        .order_by(*order)
        .limit(page.limit)
        .offset(page.offset)
    )

    items = []
    for finding, hostname in rows:
        item = FindingOut.model_validate(finding)
        item.asset_hostname = hostname
        items.append(item)

    return PaginatedResponse[FindingOut](
        items=items, total=total, limit=page.limit, offset=page.offset
    )


@router.post(
    "",
    response_model=FindingOut,
    status_code=status.HTTP_201_CREATED,
    summary="Record a finding manually",
)
async def create_finding(body: FindingCreate, current: AnalystDep, db: DbDep) -> FindingOut:
    hostname: str | None = None
    if body.asset_id:
        asset = await db.scalar(
            select(Asset).where(Asset.id == body.asset_id, Asset.org_id == current.org_id)
        )
        if asset is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
        hostname = asset.hostname

    severity = body.severity or Severity.from_cvss(body.cvss_score)
    now = datetime.now(timezone.utc)

    finding = Finding(
        org_id=current.org_id,
        asset_id=body.asset_id,
        title=body.title,
        cve_id=body.cve_id.upper() if body.cve_id else None,
        cvss_score=body.cvss_score,
        severity=severity,
        description=body.description,
        remediation=body.remediation,
        references=body.references,
        status=FindingStatus.CONFIRMED,
        source="manual",
        fingerprint=Finding.build_fingerprint(
            asset_id=body.asset_id, title=body.title, cve_id=body.cve_id
        ),
        first_seen=now,
        last_seen=now,
    )
    db.add(finding)
    await db.commit()
    await db.refresh(finding)

    out = FindingOut.model_validate(finding)
    out.asset_hostname = hostname
    return out


@router.get("/stats", response_model=FindingStatsOut, summary="Finding summary")
async def finding_stats(current: CurrentUserDep, db: DbDep) -> FindingStatsOut:
    total = (
        await db.scalar(select(func.count(Finding.id)).where(Finding.org_id == current.org_id)) or 0
    )
    open_count = (
        await db.scalar(
            select(func.count(Finding.id)).where(
                Finding.org_id == current.org_id, Finding.status.in_(_OPEN_STATUSES)
            )
        )
        or 0
    )

    sev_rows = await db.execute(
        select(Finding.severity, func.count(Finding.id))
        .where(Finding.org_id == current.org_id)
        .group_by(Finding.severity)
    )
    by_severity = {s.value: 0 for s in Severity}
    for sev, count in sev_rows:
        by_severity[sev.value] = count

    status_rows = await db.execute(
        select(Finding.status, func.count(Finding.id))
        .where(Finding.org_id == current.org_id)
        .group_by(Finding.status)
    )
    by_status = {s.value: 0 for s in FindingStatus}
    for st, count in status_rows:
        by_status[st.value] = count

    cve_rows = await db.execute(
        select(Finding.cve_id, func.count(Finding.id).label("cnt"), func.max(Finding.cvss_score))
        .where(Finding.org_id == current.org_id, Finding.cve_id.isnot(None))
        .group_by(Finding.cve_id)
        .order_by(desc("cnt"))
        .limit(10)
    )
    top_cves = [
        {"cve_id": cve, "count": count, "cvss_score": score} for cve, count, score in cve_rows
    ]

    mean_cvss = await db.scalar(
        select(func.avg(Finding.cvss_score)).where(
            Finding.org_id == current.org_id, Finding.cvss_score.isnot(None)
        )
    )

    return FindingStatsOut(
        total=total,
        open=open_count,
        by_severity=by_severity,
        by_status=by_status,
        top_cves=top_cves,
        mean_cvss=round(float(mean_cvss), 2) if mean_cvss is not None else None,
    )


@router.get("/{finding_id}", response_model=FindingOut, summary="Get one finding")
async def get_finding(finding_id: uuid.UUID, current: CurrentUserDep, db: DbDep) -> FindingOut:
    finding = await _get_finding_or_404(finding_id, current.org_id, db)
    out = FindingOut.model_validate(finding)
    out.asset_hostname = await _hostname_for(finding, current.org_id, db)
    return out


@router.patch("/{finding_id}", response_model=FindingOut, summary="Triage a finding")
async def update_finding(
    finding_id: uuid.UUID, body: FindingUpdate, current: AnalystDep, db: DbDep
) -> FindingOut:
    finding = await _get_finding_or_404(finding_id, current.org_id, db)

    data = body.model_dump(exclude_unset=True)
    notes = data.pop("notes", None)
    # Compare before the setattr loop overwrites it. Stripped, so re-saving the
    # triage form without touching the text is not recorded as a rewrite.
    remediation_changed = "remediation" in data and (data["remediation"] or "").strip() != (
        finding.remediation or ""
    ).strip()
    for field, value in data.items():
        setattr(finding, field, value)

    if notes or remediation_changed:
        # Rebuilt and reassigned rather than mutated: JSONB columns are only
        # marked dirty on assignment.
        evidence = dict(finding.evidence or {})
        if notes:
            evidence["analyst_notes"] = notes
        if remediation_changed:
            # The AI provenance described text that no longer exists. Leaving
            # remediation_source="claude" on an analyst's rewrite would put a
            # model's name against a human's advice, and the confidence and
            # uncertainty notes refer to reasoning that has been thrown away.
            evidence["remediation_source"] = SOURCE_ANALYST
            evidence["remediation_model"] = None
            evidence["remediation_confidence"] = None
            evidence["remediation_uncertain"] = []
        finding.evidence = evidence

    # Stamp resolution time when the finding leaves the open set.
    if body.status is not None:
        closed = {
            FindingStatus.REMEDIATED,
            FindingStatus.FALSE_POSITIVE,
            FindingStatus.ACCEPTED_RISK,
        }
        finding.resolved_at = datetime.now(timezone.utc) if body.status in closed else None

    await db.commit()
    await db.refresh(finding)

    out = FindingOut.model_validate(finding)
    out.asset_hostname = await _hostname_for(finding, current.org_id, db)
    return out


@router.delete("/{finding_id}", response_model=Message, summary="Delete a finding")
async def delete_finding(finding_id: uuid.UUID, current: AnalystDep, db: DbDep) -> Message:
    finding = await _get_finding_or_404(finding_id, current.org_id, db)
    await db.delete(finding)
    await db.commit()
    return Message(detail="Finding deleted")
