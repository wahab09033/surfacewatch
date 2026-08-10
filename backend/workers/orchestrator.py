"""Scan pipeline orchestration.

Builds a Celery chain of only the modules the scan config asked for, wraps it
in a callback pair so the scan row always reaches a terminal state, and captures
the change-detection baseline before the first stage runs.

Each module is its own task — they can be retried, rate-limited and scaled
independently, and a slow port scan does not block CVE enrichment for other
scans.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from celery import chain, shared_task
from celery.result import AsyncResult

from core.events import publish, terminal_event
from db.database import session_scope
from models import Scan, ScanStatus
from workers.celery_app import celery_app
from workers.context import ScanContext

# Pipeline order is fixed: later stages consume earlier output.
MODULE_ORDER: tuple[str, ...] = (
    "subdomain_enum",
    "port_scanner",
    "fingerprinter",
    "cve_correlator",
    "change_detector",
)

_TASK_NAMES: dict[str, str] = {
    "subdomain_enum": "workers.subdomain_enum.run",
    "port_scanner": "workers.port_scanner.run",
    "fingerprinter": "workers.fingerprinter.run",
    "cve_correlator": "workers.cve_correlator.run",
    "change_detector": "workers.change_detector.run",
}


def _ensure_modules_registered() -> None:
    """Import the stage modules so their tasks exist in this process's registry.

    The chain is built from task *names*, and resolving a name goes through
    ``app.tasks``, which is only populated by importing the module that declares
    the task. ``celery_app.include`` does that at worker boot, but nothing
    guarantees the module is loaded in whichever process actually resolves the
    signature — a worker started with an explicit ``-Q``/``--include``, or an
    in-process run — and the failure mode is a bare ``NotRegistered`` raised
    after the scan row is already marked RUNNING. Importing here is idempotent
    and costs one dict lookup once the modules are in ``sys.modules``.
    """
    from importlib import import_module

    for module in MODULE_ORDER:
        import_module(f"workers.{module}")


def dispatch_scan(
    *, scan_id: uuid.UUID, org_id: uuid.UUID, target: str, config: dict[str, Any]
) -> AsyncResult:
    """Queue a scan. Called from the API; returns the head task's result handle."""
    return run_pipeline.delay(
        scan_id=str(scan_id), org_id=str(org_id), target=target, config=config
    )


@shared_task(name="workers.orchestrator.run_pipeline", bind=True, max_retries=0)
def run_pipeline(
    self, scan_id: str, org_id: str, target: str, config: dict[str, Any]
) -> str:
    """Mark the scan running, snapshot the baseline, then fire the module chain."""
    ctx = ScanContext.load(scan_id=scan_id, org_id=org_id, target=target, config=config)
    ctx = ctx.for_stage("orchestrator")

    now = datetime.now(timezone.utc)
    with session_scope() as session:
        scan = session.get(Scan, ctx.scan_id)
        if scan is None:
            return "missing"
        if scan.status == ScanStatus.CANCELLED:
            return "cancelled"
        scan.status = ScanStatus.RUNNING
        scan.started_at = now
        scan.current_stage = "orchestrator"
        scan.progress = 5

    ctx.emit_status(ScanStatus.RUNNING.value, progress=5)
    ctx.log(f"Scan started for {target}")

    requested = [m for m in MODULE_ORDER if m in set(config.get("modules") or MODULE_ORDER)]
    if not requested:
        requested = list(MODULE_ORDER)
    ctx.log(f"Pipeline: {' -> '.join(requested)}")

    # Snapshot before anything mutates the inventory, so change_detector has a
    # true "before" picture.
    if "change_detector" in requested:
        from workers.change_detector import capture_baseline

        count = capture_baseline(ctx.org_id, ctx.scan_id)
        ctx.debug(f"Baseline captured for {count} existing asset(s)")

    payload = ctx.to_dict()

    _ensure_modules_registered()

    # The first task takes the context dict; each subsequent task receives the
    # previous task's return value, so signatures are immutable after the head.
    signatures = []
    for index, module in enumerate(requested):
        task_name = _TASK_NAMES[module]
        if index == 0:
            signatures.append(celery_app.signature(task_name, args=(payload,)))
        else:
            signatures.append(celery_app.signature(task_name))

    workflow = chain(*signatures)
    workflow.link(
        finalise_scan.s(scan_id=str(ctx.scan_id), org_id=str(ctx.org_id))
    )
    workflow.link_error(
        fail_scan.s(scan_id=str(ctx.scan_id), org_id=str(ctx.org_id))
    )
    workflow.apply_async()

    return "dispatched"


@shared_task(name="workers.orchestrator.finalise_scan", bind=True, max_retries=0)
def finalise_scan(self, result: Any, scan_id: str, org_id: str) -> str:
    """Success callback: close the scan out and emit the terminal event."""
    sid = uuid.UUID(scan_id)
    now = datetime.now(timezone.utc)

    with session_scope() as session:
        scan = session.get(Scan, sid)
        if scan is None:
            return "missing"
        # A cancelled scan may still have an in-flight chain; do not overwrite.
        if scan.status != ScanStatus.CANCELLED:
            scan.status = ScanStatus.COMPLETED
            scan.progress = 100
            scan.current_stage = None
        scan.completed_at = now
        final_status = scan.status
        assets = scan.assets_discovered
        findings = scan.findings_count
        duration = scan.duration_seconds

    ctx = ScanContext.load(
        scan_id=scan_id, org_id=org_id, target="", config={}, stage="orchestrator"
    )
    summary = f"Scan {final_status.value}: {assets} new asset(s), {findings} finding(s)"
    # `is not None`, not truthiness: a sub-second scan has duration 0.0 and
    # would otherwise lose its counts from the summary line.
    if duration is not None:
        summary += f" in {duration:.0f}s"
    ctx.log(summary)
    publish(
        sid,
        terminal_event(
            sid,
            final_status.value,
            assets_discovered=assets,
            findings_count=findings,
            duration_seconds=duration,
        ),
    )
    return final_status.value


@shared_task(name="workers.orchestrator.fail_scan", bind=True, max_retries=0)
def fail_scan(
    self,
    request: Any,
    exc: BaseException | None,
    traceback: str | None,
    scan_id: str,
    org_id: str,
) -> str:
    """Error callback.

    Celery calls ``link_error`` handlers with (request, exc, traceback), so the
    signature differs from the success path. The first three are typed loosely
    on purpose: they come from Celery, not from us — ``request`` is a Context
    whose shape varies with the broker, and a failed chord header can deliver
    ``exc`` already stringified rather than as an exception instance.
    """
    sid = uuid.UUID(scan_id)
    now = datetime.now(timezone.utc)
    message = str(exc)[:4000] if exc else "Unknown error"

    with session_scope() as session:
        scan = session.get(Scan, sid)
        if scan is None:
            return "missing"
        if scan.status != ScanStatus.CANCELLED:
            scan.status = ScanStatus.FAILED
            scan.error = message
            scan.current_stage = None
        scan.completed_at = now
        final_status = scan.status

    ctx = ScanContext.load(
        scan_id=scan_id, org_id=org_id, target="", config={}, stage="orchestrator"
    )
    ctx.error(f"Scan failed: {message}")
    publish(sid, terminal_event(sid, final_status.value, error=message))
    return final_status.value


__all__ = ["dispatch_scan", "fail_scan", "finalise_scan", "run_pipeline"]
