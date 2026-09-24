"""Recurring scans: create, list, edit, pause, delete.

A schedule is a standing authorisation to scan, so this router treats it with
the same care as ``routes.scans``: the target is scope-checked against the
organisation's verified domains on create, and the dispatcher re-checks it on
every run. The reason for both is that verification is revocable — a schedule
created while a domain was verified must not keep scanning it after the domain
is revoked.

Writes are Admin, reads are Analyst. Creating a recurring scan commits the
organisation to network traffic against a host indefinitely, which is a
different decision from reading the results of one.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import func, select

from config import settings
from core.deps import AdminDep, AnalystDep, DbDep
from core.scoring import OutOfScopeError, assert_in_scope
from models import Organisation, Scan, ScanCadence, ScanSchedule, ScanStatus
from models.base import utcnow
from models.scan_schedule import initial_next_run, next_occurrence
from schemas.common import Message
from schemas.schedule import ScheduleCreate, ScheduleList, ScheduleOut, ScheduleUpdate

router = APIRouter(prefix="/api/schedules", tags=["schedules"])


async def _load_schedule(
    db: DbDep, schedule_id: uuid.UUID, org_id: uuid.UUID
) -> ScanSchedule:
    """Fetch one schedule inside the caller's org.

    404 rather than 403 for another org's row: a 403 confirms the id exists,
    which is the cross-tenant enumeration oracle every query here avoids.
    """
    schedule = await db.scalar(
        select(ScanSchedule).where(
            ScanSchedule.id == schedule_id, ScanSchedule.org_id == org_id
        )
    )
    if schedule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Schedule not found")
    return schedule


async def _authorise_target(db: DbDep, org_id: uuid.UUID, target: str) -> str:
    """Scope-check ``target`` against the org's verified domains."""
    org = await db.scalar(select(Organisation).where(Organisation.id == org_id))
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organisation not found")
    try:
        return assert_in_scope(
            target, org.all_domains, allow_arbitrary=settings.allow_arbitrary_targets
        )
    except OutOfScopeError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc


async def _active_scan_count(db: DbDep, org_id: uuid.UUID) -> int:
    return await db.scalar(
        select(func.count(Scan.id)).where(
            Scan.org_id == org_id,
            Scan.status.in_([ScanStatus.QUEUED, ScanStatus.RUNNING]),
        )
    ) or 0


@router.get("", response_model=ScheduleList, summary="List recurring scans")
async def list_schedules(current: AnalystDep, db: DbDep) -> ScheduleList:
    rows = await db.scalars(
        select(ScanSchedule)
        .where(ScanSchedule.org_id == current.org_id)
        .order_by(ScanSchedule.next_run_at)
    )
    return ScheduleList(items=[ScheduleOut.from_row(r) for r in rows])


@router.post(
    "",
    response_model=ScheduleOut,
    status_code=status.HTTP_201_CREATED,
    summary="Create a recurring scan",
)
async def create_schedule(body: ScheduleCreate, current: AdminDep, db: DbDep) -> ScheduleOut:
    target = await _authorise_target(db, current.org_id, body.target)

    schedule = ScanSchedule(
        org_id=current.org_id,
        created_by=current.id,
        name=body.name,
        target=target,
        config=body.config.model_dump(),
        cadence=body.cadence,
        hour_utc=body.hour_utc,
        weekday=body.weekday,
        is_enabled=True,
        # Not due immediately — saving a schedule must not itself start a scan.
        next_run_at=initial_next_run(body.cadence, body.hour_utc, body.weekday),
    )
    db.add(schedule)
    await db.commit()
    await db.refresh(schedule)
    return ScheduleOut.from_row(schedule)


@router.get("/{schedule_id}", response_model=ScheduleOut, summary="Get one schedule")
async def get_schedule(schedule_id: uuid.UUID, current: AnalystDep, db: DbDep) -> ScheduleOut:
    return ScheduleOut.from_row(await _load_schedule(db, schedule_id, current.org_id))


@router.patch("/{schedule_id}", response_model=ScheduleOut, summary="Update a schedule")
async def update_schedule(
    schedule_id: uuid.UUID, body: ScheduleUpdate, current: AdminDep, db: DbDep
) -> ScheduleOut:
    schedule = await _load_schedule(db, schedule_id, current.org_id)

    if body.name is not None:
        schedule.name = body.name
    if body.config is not None:
        schedule.config = body.config.model_dump()
    if body.cadence is not None:
        schedule.cadence = body.cadence
        # A cadence change can invalidate the stored weekday: hourly and daily
        # have none, and leaving a stale one behind would make a later switch
        # back to weekly silently inherit a day the user did not choose.
        if body.cadence is not ScanCadence.WEEKLY:
            schedule.weekday = None
    if body.hour_utc is not None:
        schedule.hour_utc = body.hour_utc
    if body.weekday is not None:
        schedule.weekday = body.weekday

    # Re-enabling clears the reason the scheduler wrote, so a stale "the queue
    # may be unavailable" does not outlive the outage it described.
    if body.is_enabled is not None and body.is_enabled != schedule.is_enabled:
        schedule.is_enabled = body.is_enabled
        if body.is_enabled:
            schedule.consecutive_failures = 0
            schedule.disabled_reason = None

    # The edit may have produced a weekly schedule with no day.
    if schedule.cadence is ScanCadence.WEEKLY and schedule.weekday is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Choose a day of the week for a weekly schedule",
        )

    # Any timing change reschedules from now. Recomputing only when the cadence
    # moved would leave a schedule edited from "03:00" to "22:00" firing at its
    # old time once before the new one took effect.
    schedule.next_run_at = next_occurrence(
        schedule.cadence, schedule.hour_utc, schedule.weekday, after=utcnow()
    )

    await db.commit()
    await db.refresh(schedule)
    return ScheduleOut.from_row(schedule)


@router.post("/{schedule_id}/run", response_model=ScheduleOut, summary="Run a schedule now")
async def run_schedule_now(
    schedule_id: uuid.UUID, current: AnalystDep, db: DbDep
) -> ScheduleOut:
    """Queue one scan immediately, without disturbing the cadence.

    ``next_run_at`` is deliberately untouched: this is "also run now", not
    "shift the schedule". Recomputing it would move a daily 03:00 schedule to
    whatever time the button happened to be pressed.
    """
    schedule = await _load_schedule(db, schedule_id, current.org_id)

    # Authorisation is re-checked even though the dispatcher will check again.
    # The dispatcher's check is the security boundary; this one is what turns a
    # revoked domain into a 403 the user can read, rather than a schedule that
    # appears to run and produces nothing.
    target = await _authorise_target(db, current.org_id, schedule.target)

    if await _active_scan_count(db, current.org_id) >= settings.max_concurrent_scans_per_org:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                "You already have the maximum number of scans queued or running "
                f"(limit {settings.max_concurrent_scans_per_org}). Wait for one to finish."
            ),
        )

    scan = Scan(
        org_id=current.org_id,
        created_by=current.id,
        target=target,
        status=ScanStatus.QUEUED,
        config=dict(schedule.config or {}),
    )
    db.add(scan)
    await db.flush()

    schedule.last_scan_id = scan.id
    schedule.last_run_at = utcnow()
    await db.commit()
    await db.refresh(schedule)

    from workers.orchestrator import dispatch_scan

    # Same ordering as routes.scans.create_scan: the row is committed before the
    # broker call, because the worker loads it the instant the task is picked
    # up. A broker failure therefore leaves a committed scan behind and it has
    # to be reconciled explicitly, or it sits "queued" forever counting against
    # the org's concurrency limit.
    try:
        task = dispatch_scan(
            scan_id=scan.id, org_id=current.org_id, target=target, config=scan.config
        )
    except Exception as exc:
        scan.status = ScanStatus.FAILED
        scan.completed_at = utcnow()
        scan.error = f"Could not queue the scan: {exc.__class__.__name__}"
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The scan queue is unavailable right now. Please try again shortly.",
        ) from exc

    scan.celery_task_id = task.id
    await db.commit()
    return ScheduleOut.from_row(schedule)


@router.delete("/{schedule_id}", response_model=Message, summary="Delete a schedule")
async def delete_schedule(schedule_id: uuid.UUID, current: AdminDep, db: DbDep) -> Message:
    schedule = await _load_schedule(db, schedule_id, current.org_id)
    # Scans it already produced are untouched: they are ordinary rows in
    # ``scans``, and ``last_scan_id`` points the other way, so deleting the
    # schedule cannot take the history with it.
    await db.delete(schedule)
    await db.commit()
    return Message(detail="Schedule deleted")
