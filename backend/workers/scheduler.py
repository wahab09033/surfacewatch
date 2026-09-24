"""The beat-driven background work: scheduled scans, retention, re-verification.

Nothing here is triggered by a user request. Celery beat calls these on a timer,
which makes them the only code in the system that runs with no request context —
no authenticated user, no org, and no error response anyone will read. Everything
they do therefore has to be recoverable and self-reporting: a task that raises
leaves no trace a customer can see, so failures are written onto the rows they
concern (``ScanSchedule.disabled_reason``, ``Scan.error``) rather than only into
a worker log nobody is tailing.

**Why dispatch is two phases.** A scan row has to exist before the task is
published, because the worker loads it the instant the task is picked up — a
task that arrives first is a race we lose. But the row is also the only record
that a scan was meant to happen, and publishing to the broker can fail. So phase
one (one transaction, row locks held) creates every scan row and advances every
schedule; phase two talks to the broker and reconciles whatever comes back. The
alternative — dispatching inside the transaction — holds row locks across a
network call to Redis, and any failure there rolls back the schedule advance,
which means the same window fires again on the next tick, forever.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from celery import shared_task
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from config import settings
from core.scoring import OutOfScopeError, assert_in_scope
from db.database import session_scope
from models import (
    DomainVerification,
    DomainVerificationStatus,
    Organisation,
    Report,
    Scan,
    ScanLog,
    ScanSchedule,
    ScanStatus,
)
from models.base import utcnow

logger = logging.getLogger(__name__)

# Upper bound on schedules fired in a single tick.
#
# A tick that tries to dispatch thousands of scans at once will not finish
# inside its own interval, and beat's next tick then overlaps it — two
# dispatchers racing for the same rows. The row lock (``skip_locked``) makes
# that safe but not fast, and the backlog is better drained in bounded batches.
# Anything still due is picked up by the next tick, which is why the ordering
# below is oldest-first.
_MAX_PER_TICK = 100

# Concurrency for the weekly DNS re-check. Each pending check holds a UDP socket
# and a resolver timeout, so an unbounded gather over a large estate is a
# self-inflicted denial of service against our own resolver.
_REVERIFY_CONCURRENCY = 20


# --- Scheduled scans --------------------------------------------------------


def _disable(schedule: ScanSchedule, reason: str) -> None:
    """Switch a schedule off, recording why.

    Autodisabling is only defensible if the reason is visible. A schedule that
    quietly stops running and reports nothing is worse than one that keeps
    failing loudly, because the customer believes their estate is being scanned.
    """
    schedule.is_enabled = False
    schedule.disabled_reason = reason


def dispatch_due_scans(now: datetime | None = None) -> dict[str, int]:
    """Queue one scan for every enabled schedule whose window has arrived.

    Returns counters rather than raising, because a tick that fails partway must
    still report what it managed to do — those scans are real and running.
    """
    moment = (now or utcnow()).astimezone(timezone.utc)
    counters = {"due": 0, "queued": 0, "skipped": 0, "disabled": 0, "failed": 0}
    pending: list[tuple[uuid.UUID, uuid.UUID, uuid.UUID, str, dict]] = []

    with session_scope() as session:
        due = session.scalars(
            select(ScanSchedule)
            .where(ScanSchedule.is_enabled.is_(True), ScanSchedule.next_run_at <= moment)
            .order_by(ScanSchedule.next_run_at)
            .limit(_MAX_PER_TICK)
            # skip_locked, not a plain FOR UPDATE: a second dispatcher (beat
            # restarted mid-tick, or two beat replicas) must skip rows this one
            # holds rather than block on them until the tick finishes.
            .with_for_update(skip_locked=True)
        ).all()
        counters["due"] = len(due)

        # Counted once per organisation, then incremented in memory as this tick
        # queues work — otherwise two schedules for the same org in one tick
        # both see the same pre-tick count and together exceed the cap.
        active_by_org: dict[uuid.UUID, int] = {}

        for schedule in due:
            # Advanced first, before any branch that could `continue`. Every
            # exit path below leaves next_run_at in the future, so no failure
            # mode re-fires the same window on the next tick.
            schedule.advance(after=moment)
            schedule.last_run_at = moment

            org = session.get(Organisation, schedule.org_id)
            if org is None or not org.is_active:
                _disable(schedule, "The organisation is no longer active.")
                counters["disabled"] += 1
                continue

            # Re-checked on every run, not just at creation. A domain can be
            # revoked between two ticks — that is the entire point of the
            # re-verification sweep — and a schedule that skips this check would
            # keep scanning a domain the org no longer controls.
            try:
                target = assert_in_scope(
                    schedule.target,
                    org.all_domains,
                    allow_arbitrary=settings.allow_arbitrary_targets,
                )
            except OutOfScopeError as exc:
                _disable(schedule, f"Target is no longer authorised: {exc}")
                counters["disabled"] += 1
                continue

            if schedule.org_id not in active_by_org:
                active_by_org[schedule.org_id] = session.scalar(
                    select(func.count(Scan.id)).where(
                        Scan.org_id == schedule.org_id,
                        Scan.status.in_([ScanStatus.QUEUED, ScanStatus.RUNNING]),
                    )
                ) or 0

            if active_by_org[schedule.org_id] >= settings.max_concurrent_scans_per_org:
                # The window is deliberately missed rather than queued. A
                # tenant at their concurrency cap is already scanning as much
                # as they are allowed to; holding this run back would hand them
                # a burst the moment the cap frees up, which is the catch-up
                # behaviour next_run_at exists to prevent.
                logger.info(
                    "Schedule %s skipped: org %s is at its concurrent scan limit",
                    schedule.id,
                    schedule.org_id,
                )
                counters["skipped"] += 1
                continue

            config = dict(schedule.config or {})
            scan = Scan(
                org_id=schedule.org_id,
                # NULL author: no user asked for this. The UI renders it as
                # "scheduled" rather than attributing it to whoever happened to
                # create the schedule, who may since have left.
                created_by=None,
                target=target,
                status=ScanStatus.QUEUED,
                config=config,
            )
            session.add(scan)
            # The id is a Python-side default applied at flush, so last_scan_id
            # would otherwise be set to None.
            session.flush()
            schedule.last_scan_id = scan.id
            active_by_org[schedule.org_id] += 1
            pending.append((schedule.id, scan.id, schedule.org_id, target, config))

    if pending:
        _publish(pending, counters)

    if any(counters.values()):
        logger.info("Scheduled dispatch: %s", counters)
    return counters


def _publish(pending: list[tuple[uuid.UUID, uuid.UUID, uuid.UUID, str, dict]], counters: dict) -> None:
    """Hand each queued scan to the broker. Phase two — no transaction is open."""
    # Imported here so the module stays importable without a broker connection.
    from workers.orchestrator import dispatch_scan

    for schedule_id, scan_id, org_id, target, config in pending:
        try:
            task = dispatch_scan(scan_id=scan_id, org_id=org_id, target=target, config=config)
        except Exception as exc:  # noqa: BLE001 — any broker error is the same story
            logger.exception("Scheduled scan %s could not be queued", scan_id)
            _record_failure(schedule_id=schedule_id, scan_id=scan_id, exc=exc)
            counters["failed"] += 1
            continue
        _record_success(schedule_id=schedule_id, scan_id=scan_id, task_id=task.id)
        counters["queued"] += 1


def _record_success(*, schedule_id: uuid.UUID, scan_id: uuid.UUID, task_id: str) -> None:
    with session_scope() as session:
        scan = session.get(Scan, scan_id)
        if scan is not None:
            scan.celery_task_id = task_id
        schedule = session.get(ScanSchedule, schedule_id)
        # Only cleared on an actual success, so the counter measures
        # consecutive failures rather than lifetime ones.
        if schedule is not None and schedule.consecutive_failures:
            schedule.consecutive_failures = 0


def _record_failure(*, schedule_id: uuid.UUID, scan_id: uuid.UUID, exc: Exception) -> None:
    with session_scope() as session:
        scan = session.get(Scan, scan_id)
        if scan is not None:
            # The row was committed before the broker call, so a publish failure
            # leaves a scan that no worker will ever run. Left queued it would
            # count against the org's concurrency limit forever.
            scan.status = ScanStatus.FAILED
            scan.completed_at = utcnow()
            # Class name only: the kombu message carries the broker host and
            # port, and this field is rendered in the tenant's console.
            scan.error = f"Could not queue the scan: {exc.__class__.__name__}"

        schedule = session.get(ScanSchedule, schedule_id)
        if schedule is None:
            return
        schedule.consecutive_failures += 1
        if schedule.consecutive_failures >= settings.schedule_max_consecutive_failures:
            _disable(
                schedule,
                f"Disabled after {schedule.consecutive_failures} consecutive failures to "
                "queue a scan. The scan queue may be unavailable.",
            )


@shared_task(name="workers.scheduler.dispatch_due_scans")
def scheduled_dispatch() -> dict[str, int]:
    """Beat entry point. See ``dispatch_due_scans`` for the logic."""
    return dispatch_due_scans()


# --- Retention --------------------------------------------------------------


def _unlink_report_file(path: str | None) -> bool:
    """Delete a report's file. False when it is still on disk afterwards."""
    if not path:
        # A row with no path has nothing to unlink, so nothing is left behind.
        return True
    try:
        Path(path).unlink(missing_ok=True)
        return True
    except OSError as exc:
        # A file we cannot delete is a human's problem: the row stays so the
        # path is still recorded somewhere, and the next sweep tries again.
        logger.warning("Could not delete report file %s: %s", path, exc)
        return False


@shared_task(name="workers.scheduler.prune_old_data")
def prune_old_data() -> dict[str, int]:
    """Drop old log lines, and optionally whole scans and reports.

    Each sweep is disabled by a 0 setting, so the dangerous ones stay off until
    an operator opts in — see the retention block in config.py for why deleting
    scans is not the default.
    """
    now = utcnow()
    deleted = {"scan_logs": 0, "scans": 0, "reports": 0, "report_files": 0}

    if settings.retention_scan_log_days > 0:
        cutoff = now - timedelta(days=settings.retention_scan_log_days)
        with session_scope() as session:
            # Logs belonging to a scan that is still running are exempt. A scan
            # is capped at an hour so this should never match, but the cost of
            # being wrong is a live scan whose history vanishes mid-run and a
            # WebSocket client that cannot replay it.
            active = select(Scan.id).where(
                Scan.status.in_([ScanStatus.QUEUED, ScanStatus.RUNNING])
            )
            deleted["scan_logs"] = session.execute(
                delete(ScanLog).where(
                    ScanLog.timestamp < cutoff, ScanLog.scan_id.not_in(active)
                )
            ).rowcount or 0

    if settings.retention_scan_days > 0:
        cutoff = now - timedelta(days=settings.retention_scan_days)
        with session_scope() as session:
            # The FK cascades take the logs and findings with it. That is the
            # point of the setting, and the reason it is off by default.
            deleted["scans"] = session.execute(
                delete(Scan).where(
                    Scan.created_at < cutoff,
                    Scan.status.not_in([ScanStatus.QUEUED, ScanStatus.RUNNING]),
                )
            ).rowcount or 0

    if settings.retention_report_days > 0:
        cutoff = now - timedelta(days=settings.retention_report_days)
        with session_scope() as session:
            for report in session.scalars(select(Report).where(Report.created_at < cutoff)):
                if not _unlink_report_file(report.file_path):
                    continue
                session.delete(report)
                deleted["reports"] += 1
                deleted["report_files"] += 1

    logger.info("Retention sweep: %s", deleted)
    return deleted


# --- Domain re-verification -------------------------------------------------


async def _recheck(
    pairs: list[tuple[uuid.UUID, str, str]]
) -> dict[uuid.UUID, tuple[bool, str | None]]:
    """Re-run the TXT challenge for each (id, domain, token) triple."""
    from core.dns_verify import check_domain_token

    semaphore = asyncio.Semaphore(_REVERIFY_CONCURRENCY)

    async def one(claim_id: uuid.UUID, domain: str, token: str):
        async with semaphore:
            try:
                return claim_id, await check_domain_token(domain, token)
            except Exception as exc:  # noqa: BLE001 — one bad domain must not end the sweep
                logger.warning("Re-verification of %s raised: %s", domain, exc)
                return claim_id, None

    return {cid: (r.ok, r.error) for cid, r in await asyncio.gather(*(one(*p) for p in pairs)) if r}


@shared_task(name="workers.scheduler.reverify_domains")
def reverify_domains() -> dict[str, int]:
    """Weekly re-check of every verified domain's DNS challenge.

    This is the control that closes the gap in a one-time check. Verification
    proves ownership at a moment; domains change hands, and a record that has
    since been removed is the signal that the claim is stale. Scanning someone
    else's domain because they let the registration lapse is exactly the
    liability this feature exists to avoid.

    Revocation is gated behind ``domain_reverify_failure_threshold``, which
    defaults to 0 (never). The sweep always records what it found.
    """
    counters = {"checked": 0, "failed": 0, "revoked": 0, "unresolved": 0}
    if not settings.domain_reverify_enabled:
        return counters

    with session_scope() as session:
        pairs = [
            (row.id, row.domain, row.token)
            for row in session.scalars(
                select(DomainVerification).where(
                    DomainVerification.status == DomainVerificationStatus.VERIFIED
                )
            )
        ]

    if not pairs:
        return counters

    results = asyncio.run(_recheck(pairs))

    with session_scope() as session:
        for claim_id, (ok, error) in results.items():
            claim = session.get(DomainVerification, claim_id)
            if claim is None:  # deleted while the sweep was running
                continue
            counters["checked"] += 1
            claim.last_checked_at = utcnow()

            if ok:
                claim.consecutive_failures = 0
                claim.last_error = None
                continue

            counters["failed"] += 1
            claim.consecutive_failures += 1
            claim.last_error = error
            # A DNS failure we could not complete is not evidence of anything,
            # so it is reported and counted but never accumulates toward
            # revocation.
            if error and "Could not check DNS" in error:
                counters["unresolved"] += 1
                continue
            if not _should_revoke(claim):
                continue
            _revoke(session, claim)
            counters["revoked"] += 1

    logger.info("Domain re-verification: %s", counters)
    return counters


def _should_revoke(claim: DomainVerification) -> bool:
    threshold = settings.domain_reverify_failure_threshold
    return threshold > 0 and claim.consecutive_failures >= threshold


def _revoke(session: Session, claim: DomainVerification) -> None:
    """Withdraw a domain's scanning authority and switch off what depended on it.

    Both halves are required. Clearing ``verified_domains`` stops new scans, but
    an existing schedule re-checks scope only when it fires — so without the
    second step a revoked domain keeps producing scans until someone notices.
    """
    org = session.get(Organisation, claim.org_id)
    claim.status = DomainVerificationStatus.FAILED
    claim.verified_at = None
    if org is not None:
        # Reassignment, not mutation: verified_domains is a plain JSONB column,
        # so an in-place .remove() is silently dropped at commit.
        org.verified_domains = [d for d in (org.verified_domains or []) if d and d != claim.domain]

        reason = (
            f"The domain {claim.domain} failed {claim.consecutive_failures} consecutive "
            "DNS re-checks and is no longer verified. Re-verify it to resume."
        )
        for schedule in session.scalars(
            select(ScanSchedule).where(
                ScanSchedule.org_id == claim.org_id, ScanSchedule.is_enabled.is_(True)
            )
        ):
            if schedule.target == claim.domain or schedule.target.endswith(f".{claim.domain}"):
                _disable(schedule, reason)

    logger.warning(
        "Revoked %s for org %s after %d consecutive failures",
        claim.domain,
        claim.org_id,
        claim.consecutive_failures,
    )


__all__ = [
    "dispatch_due_scans",
    "prune_old_data",
    "reverify_domains",
    "scheduled_dispatch",
]
