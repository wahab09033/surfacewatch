"""Scan lifecycle: queue, monitor, cancel, inspect logs."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from core.deps import AnalystDep, CurrentUserDep, DbDep, PaginationDep
from core.events import publish, terminal_event
from core.scoring import OutOfScopeError, assert_in_scope
from models import Organisation, Scan, ScanLog, ScanStatus
from schemas.common import Message, PaginatedResponse
from schemas.scan import ScanCreate, ScanLogOut, ScanOut

router = APIRouter(prefix="/api/scans", tags=["scans"])

logger = logging.getLogger(__name__)


def _to_out(scan: Scan) -> ScanOut:
    out = ScanOut.model_validate(scan)
    out.duration_seconds = scan.duration_seconds
    return out


async def _get_scan_or_404(scan_id: uuid.UUID, org_id: uuid.UUID, db: AsyncSession) -> Scan:
    """Fetch a scan inside the caller's org.

    The ``org_id`` predicate is what makes cross-tenant access impossible: a
    valid id from another organisation is indistinguishable from a missing one.
    """
    scan = await db.scalar(select(Scan).where(Scan.id == scan_id, Scan.org_id == org_id))
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return scan


@router.post(
    "",
    response_model=ScanOut,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Queue a new scan",
)
async def create_scan(body: ScanCreate, current: AnalystDep, db: DbDep) -> ScanOut:
    org = await db.scalar(select(Organisation).where(Organisation.id == current.org_id))
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organisation not found")

    # Authorisation check before a single packet leaves the box: the target
    # must fall inside a domain this tenant has verified.
    try:
        target = assert_in_scope(
            body.target, org.all_domains, allow_arbitrary=settings.allow_arbitrary_targets
        )
    except OutOfScopeError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc

    active = await db.scalar(
        select(func.count(Scan.id)).where(
            Scan.org_id == current.org_id,
            Scan.status.in_([ScanStatus.QUEUED, ScanStatus.RUNNING]),
        )
    )
    # Guard against a single tenant saturating the worker pool. The limit is a
    # setting rather than a constant here because workers.scheduler enforces the
    # same ceiling on scheduled scans, and two copies of one limit drift.
    if (active or 0) >= settings.max_concurrent_scans_per_org:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"You already have {active} scans queued or running "
                f"(limit {settings.max_concurrent_scans_per_org}). Wait for one to finish."
            ),
        )

    scan = Scan(
        org_id=current.org_id,
        created_by=current.id,
        target=target,
        status=ScanStatus.QUEUED,
        config=body.config.model_dump(),
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Import here: the API process should not pull in worker deps at startup.
    from workers.orchestrator import dispatch_scan

    # The row is committed before the broker call, because the worker needs to
    # be able to load it the moment the task is picked up — a task that arrives
    # before its row exists is a race we would lose. That ordering means a
    # broker failure here leaves a committed scan behind, so it has to be
    # cleaned up explicitly: an unreachable Redis would otherwise strand the
    # scan in "queued" forever, showing a customer a scan that no worker will
    # ever run and that counts against their concurrency limit.
    try:
        task = dispatch_scan(
            scan_id=scan.id, org_id=current.org_id, target=target, config=scan.config
        )
    except Exception as exc:
        logger.exception("Failed to dispatch scan %s to the broker", scan.id)
        scan.status = ScanStatus.FAILED
        scan.completed_at = datetime.now(timezone.utc)
        # Class name only. The message from kombu carries the broker host and
        # port, and this field is rendered in the tenant's console — the full
        # detail belongs in the log line above, not in customer-visible output.
        scan.error = f"Could not queue the scan: {exc.__class__.__name__}"
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The scan queue is unavailable right now. Please try again shortly.",
        ) from exc

    scan.celery_task_id = task.id
    await db.commit()
    await db.refresh(scan)

    return _to_out(scan)


@router.get("", response_model=PaginatedResponse[ScanOut], summary="List scans")
async def list_scans(
    current: CurrentUserDep,
    db: DbDep,
    page: PaginationDep,
    status_filter: ScanStatus | None = Query(default=None, alias="status"),
    target: str | None = Query(default=None, description="Substring match on target"),
) -> PaginatedResponse[ScanOut]:
    conditions = [Scan.org_id == current.org_id]
    if status_filter is not None:
        conditions.append(Scan.status == status_filter)
    if target:
        conditions.append(Scan.target.ilike(f"%{target}%"))

    total = await db.scalar(select(func.count(Scan.id)).where(*conditions)) or 0
    rows = await db.scalars(
        select(Scan)
        .where(*conditions)
        .order_by(desc(Scan.created_at))
        .limit(page.limit)
        .offset(page.offset)
    )
    return PaginatedResponse[ScanOut](
        items=[_to_out(s) for s in rows], total=total, limit=page.limit, offset=page.offset
    )


@router.get("/stats", summary="Scan activity summary")
async def scan_stats(current: CurrentUserDep, db: DbDep) -> dict:
    since = datetime.now(timezone.utc) - timedelta(days=7)
    rows = await db.execute(
        select(Scan.status, func.count(Scan.id)).where(Scan.org_id == current.org_id).group_by(Scan.status)
    )
    by_status = {s.value: 0 for s in ScanStatus}
    for scan_status, count in rows:
        by_status[scan_status.value] = count

    last_7d = await db.scalar(
        select(func.count(Scan.id)).where(Scan.org_id == current.org_id, Scan.created_at >= since)
    )
    return {
        "by_status": by_status,
        "total": sum(by_status.values()),
        "last_7d": last_7d or 0,
        "active": by_status[ScanStatus.QUEUED.value] + by_status[ScanStatus.RUNNING.value],
    }


@router.get("/{scan_id}", response_model=ScanOut, summary="Get one scan")
async def get_scan(scan_id: uuid.UUID, current: CurrentUserDep, db: DbDep) -> ScanOut:
    return _to_out(await _get_scan_or_404(scan_id, current.org_id, db))


@router.get(
    "/{scan_id}/logs",
    response_model=PaginatedResponse[ScanLogOut],
    summary="Persisted log lines for a scan",
)
async def get_scan_logs(
    scan_id: uuid.UUID,
    current: CurrentUserDep,
    db: DbDep,
    page: PaginationDep,
) -> PaginatedResponse[ScanLogOut]:
    await _get_scan_or_404(scan_id, current.org_id, db)

    total = await db.scalar(select(func.count(ScanLog.id)).where(ScanLog.scan_id == scan_id)) or 0
    rows = await db.scalars(
        select(ScanLog)
        .where(ScanLog.scan_id == scan_id)
        .order_by(ScanLog.timestamp)
        .limit(page.limit)
        .offset(page.offset)
    )
    return PaginatedResponse[ScanLogOut](
        items=[ScanLogOut.model_validate(r) for r in rows],
        total=total,
        limit=page.limit,
        offset=page.offset,
    )


@router.post("/{scan_id}/cancel", response_model=ScanOut, summary="Cancel a running scan")
async def cancel_scan(scan_id: uuid.UUID, current: AnalystDep, db: DbDep) -> ScanOut:
    scan = await _get_scan_or_404(scan_id, current.org_id, db)
    if scan.status.is_terminal:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scan is already {scan.status.value}",
        )

    if scan.celery_task_id:
        from workers.celery_app import celery_app

        celery_app.control.revoke(scan.celery_task_id, terminate=True, signal="SIGTERM")

    scan.status = ScanStatus.CANCELLED
    scan.completed_at = datetime.now(timezone.utc)
    scan.current_stage = None
    await db.commit()
    await db.refresh(scan)

    # Unblock any WebSocket clients still waiting on this channel.
    publish(scan.id, terminal_event(scan.id, ScanStatus.CANCELLED.value))
    return _to_out(scan)


@router.delete("/{scan_id}", response_model=Message, summary="Delete a scan and its logs")
async def delete_scan(scan_id: uuid.UUID, current: AnalystDep, db: DbDep) -> Message:
    scan = await _get_scan_or_404(scan_id, current.org_id, db)
    if scan.status in {ScanStatus.QUEUED, ScanStatus.RUNNING}:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cancel the scan before deleting it",
        )
    await db.delete(scan)
    await db.commit()
    return Message(detail="Scan deleted")
