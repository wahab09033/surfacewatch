"""Report generation and the dashboard aggregate."""

from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy import desc, func, select

from config import settings
from core.deps import AnalystDep, CurrentUserDep, DbDep, PaginationDep
from models import (
    Asset,
    Finding,
    FindingStatus,
    Organisation,
    Report,
    Scan,
    ScanStatus,
    Severity,
)
from schemas.common import Message, PaginatedResponse
from schemas.report import DashboardOut, ReportOut, ReportRequest

router = APIRouter(prefix="/api/reports", tags=["reports"])

logger = logging.getLogger(__name__)

_OPEN_STATUSES = [FindingStatus.OPEN, FindingStatus.TRIAGED, FindingStatus.CONFIRMED]


@router.get("/dashboard", response_model=DashboardOut, summary="Dashboard counters")
async def dashboard(current: CurrentUserDep, db: DbDep) -> DashboardOut:
    since = datetime.now(timezone.utc) - timedelta(days=7)

    assets_total = (
        await db.scalar(select(func.count(Asset.id)).where(Asset.org_id == current.org_id)) or 0
    )
    assets_new = (
        await db.scalar(
            select(func.count(Asset.id)).where(
                Asset.org_id == current.org_id, Asset.first_seen >= since
            )
        )
        or 0
    )
    findings_open = (
        await db.scalar(
            select(func.count(Finding.id)).where(
                Finding.org_id == current.org_id, Finding.status.in_(_OPEN_STATUSES)
            )
        )
        or 0
    )

    sev_rows = await db.execute(
        select(Finding.severity, func.count(Finding.id))
        .where(Finding.org_id == current.org_id, Finding.status.in_(_OPEN_STATUSES))
        .group_by(Finding.severity)
    )
    by_severity = {s.value: 0 for s in Severity}
    for sev, count in sev_rows:
        by_severity[sev.value] = count

    scans_running = (
        await db.scalar(
            select(func.count(Scan.id)).where(
                Scan.org_id == current.org_id,
                Scan.status.in_([ScanStatus.QUEUED, ScanStatus.RUNNING]),
            )
        )
        or 0
    )
    scans_recent = (
        await db.scalar(
            select(func.count(Scan.id)).where(
                Scan.org_id == current.org_id, Scan.created_at >= since
            )
        )
        or 0
    )

    mean_risk = await db.scalar(
        select(func.avg(Asset.risk_score)).where(Asset.org_id == current.org_id)
    )

    top_assets = await db.scalars(
        select(Asset)
        .where(Asset.org_id == current.org_id)
        .order_by(desc(Asset.risk_score))
        .limit(5)
    )
    top_risk = [
        {
            "id": str(a.id),
            "hostname": a.hostname,
            "risk_score": a.risk_score,
            "open_ports": a.open_ports,
            "technologies": a.technologies[:5],
        }
        for a in top_assets
    ]

    recent_rows = await db.execute(
        select(Finding, Asset.hostname)
        # Org-scoped on the join as well as the filter — see the same join in
        # routes/findings.py for why the finding's own org_id is not enough.
        .outerjoin(Asset, (Asset.id == Finding.asset_id) & (Asset.org_id == current.org_id))
        .where(Finding.org_id == current.org_id, Finding.status.in_(_OPEN_STATUSES))
        .order_by(desc(Finding.created_at))
        .limit(10)
    )
    recent = [
        {
            "id": str(f.id),
            "title": f.title,
            "severity": f.severity.value,
            "cve_id": f.cve_id,
            "cvss_score": f.cvss_score,
            "hostname": hostname,
            "created_at": f.created_at.isoformat(),
        }
        for f, hostname in recent_rows
    ]

    return DashboardOut(
        assets_total=assets_total,
        assets_new_7d=assets_new,
        findings_open=findings_open,
        findings_by_severity=by_severity,
        scans_running=scans_running,
        scans_last_7d=scans_recent,
        mean_risk_score=round(float(mean_risk), 1) if mean_risk is not None else 0.0,
        top_risk_assets=top_risk,
        recent_findings=recent,
    )


@router.post(
    "",
    response_model=ReportOut,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Generate a report",
)
async def create_report(body: ReportRequest, current: AnalystDep, db: DbDep) -> Report:
    if body.scan_id:
        scan = await db.scalar(
            select(Scan).where(Scan.id == body.scan_id, Scan.org_id == current.org_id)
        )
        if scan is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    org = await db.scalar(select(Organisation).where(Organisation.id == current.org_id))
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organisation not found")

    now = datetime.now(timezone.utc)
    filename = f"surfacewatch-{current.org_id}-{now:%Y%m%d-%H%M%S}.{body.format}"
    # Reports are partitioned per org on disk, but access always goes through
    # the download endpoint below so the org check cannot be bypassed.
    file_path = os.path.join(settings.report_output_dir, str(current.org_id), filename)

    report = Report(
        org_id=current.org_id,
        generated_by=current.id,
        generated_at=now,
        file_path=file_path,
        title=body.title or f"{org.name} attack surface report",
        format=body.format,
        status="pending",
        summary={"filters": body.model_dump(mode="json")},
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)

    from workers.report_builder import build_report

    # As in create_scan: the row is committed first so the worker can load it,
    # which means a broker failure has to be undone here. Without this the
    # report is stranded in "pending" — and the reports page polls for as long
    # as anything is pending, so it would refresh forever against a job that
    # was never queued.
    try:
        build_report.delay(
            report_id=str(report.id),
            org_id=str(current.org_id),
            options=body.model_dump(mode="json"),
        )
    except Exception as exc:
        logger.exception("Failed to dispatch report %s to the broker", report.id)
        report.status = "failed"
        # summary is JSONB and reassigned wholesale: mutating it in place would
        # not mark the attribute dirty, and the update would be dropped.
        report.summary = {**report.summary, "error": "Could not queue the report"}
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The report queue is unavailable right now. Please try again shortly.",
        ) from exc

    return report


@router.get("", response_model=PaginatedResponse[ReportOut], summary="List reports")
async def list_reports(
    current: CurrentUserDep, db: DbDep, page: PaginationDep
) -> PaginatedResponse[ReportOut]:
    conditions = [Report.org_id == current.org_id]
    total = await db.scalar(select(func.count(Report.id)).where(*conditions)) or 0
    rows = await db.scalars(
        select(Report)
        .where(*conditions)
        .order_by(desc(Report.generated_at))
        .limit(page.limit)
        .offset(page.offset)
    )
    return PaginatedResponse[ReportOut](
        items=[ReportOut.model_validate(r) for r in rows],
        total=total,
        limit=page.limit,
        offset=page.offset,
    )


@router.get("/{report_id}", response_model=ReportOut, summary="Get report metadata")
async def get_report(report_id: uuid.UUID, current: CurrentUserDep, db: DbDep) -> Report:
    report = await db.scalar(
        select(Report).where(Report.id == report_id, Report.org_id == current.org_id)
    )
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    return report


@router.get("/{report_id}/download", summary="Download the generated file")
async def download_report(report_id: uuid.UUID, current: CurrentUserDep, db: DbDep) -> FileResponse:
    report = await db.scalar(
        select(Report).where(Report.id == report_id, Report.org_id == current.org_id)
    )
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    if report.status != "ready":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Report is {report.status}; not ready for download",
        )

    # The stored path is server-generated, but re-anchor it under the configured
    # output directory so a tampered row cannot read arbitrary files.
    root = os.path.realpath(settings.report_output_dir)
    resolved = os.path.realpath(report.file_path)
    if not resolved.startswith(root + os.sep) or not os.path.isfile(resolved):
        raise HTTPException(
            status_code=status.HTTP_410_GONE, detail="Report file is no longer available"
        )

    media = {
        "pdf": "application/pdf",
        "json": "application/json",
        "csv": "text/csv",
    }.get(report.format, "application/octet-stream")

    return FileResponse(resolved, media_type=media, filename=os.path.basename(resolved))


@router.delete("/{report_id}", response_model=Message, summary="Delete a report")
async def delete_report(report_id: uuid.UUID, current: AnalystDep, db: DbDep) -> Message:
    report = await db.scalar(
        select(Report).where(Report.id == report_id, Report.org_id == current.org_id)
    )
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    root = os.path.realpath(settings.report_output_dir)
    resolved = os.path.realpath(report.file_path)
    if resolved.startswith(root + os.sep) and os.path.isfile(resolved):
        try:
            os.remove(resolved)
        except OSError:
            pass  # row still goes away; orphaned file is swept by ops

    await db.delete(report)
    await db.commit()
    return Message(detail="Report deleted")
