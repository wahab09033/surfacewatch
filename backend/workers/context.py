"""Shared plumbing for scan modules.

``ScanContext`` gives every module one way to log: a line goes to Postgres
(durable history) and to the Redis channel ``scan:{scan_id}:logs`` (live
WebSocket feed) in the same call.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from sqlalchemy import select

from core.events import log_event, publish, result_event, status_event
from db.database import session_scope
from models import LogLevel, Organisation, Scan, ScanLog, ScanStatus

logger = logging.getLogger(__name__)


@dataclass
class ScanContext:
    """Per-scan state passed between pipeline stages.

    Celery tasks exchange plain dicts (JSON serialisable), so this object is
    rebuilt at the head of each task via ``ScanContext.load``.
    """

    scan_id: uuid.UUID
    org_id: uuid.UUID
    target: str
    config: dict[str, Any] = field(default_factory=dict)
    stage: str | None = None

    # --- Construction ------------------------------------------------------

    @classmethod
    def load(cls, scan_id: str | uuid.UUID, org_id: str | uuid.UUID, target: str,
             config: dict[str, Any] | None = None, stage: str | None = None) -> "ScanContext":
        return cls(
            scan_id=uuid.UUID(str(scan_id)),
            org_id=uuid.UUID(str(org_id)),
            target=target,
            config=config or {},
            stage=stage,
        )

    def for_stage(self, stage: str) -> "ScanContext":
        return ScanContext(
            scan_id=self.scan_id,
            org_id=self.org_id,
            target=self.target,
            config=self.config,
            stage=stage,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": str(self.scan_id),
            "org_id": str(self.org_id),
            "target": self.target,
            "config": self.config,
            "stage": self.stage,
        }

    # --- Config accessors --------------------------------------------------

    @property
    def modules(self) -> list[str]:
        return list(self.config.get("modules") or [])

    @property
    def passive_only(self) -> bool:
        return bool(self.config.get("passive_only"))

    def option(self, key: str, default: Any = None) -> Any:
        return self.config.get(key, default)

    # --- Logging -----------------------------------------------------------

    def log(
        self,
        message: str,
        *,
        level: LogLevel | str = LogLevel.INFO,
        persist: bool = True,
    ) -> None:
        """Emit one log line to both sinks."""
        lvl = LogLevel(level) if isinstance(level, str) else level
        now = datetime.now(timezone.utc)

        if persist:
            try:
                with session_scope() as session:
                    session.add(
                        ScanLog(
                            scan_id=self.scan_id,
                            timestamp=now,
                            message=message[:8000],
                            level=lvl,
                            stage=self.stage,
                        )
                    )
            except Exception:
                # Never let a log write abort a scan.
                logger.exception("failed to persist scan log for %s", self.scan_id)

        publish(
            self.scan_id,
            log_event(
                self.scan_id, message, level=lvl.value, stage=self.stage, timestamp=now
            ),
        )
        logger.log(_LOGGING_LEVELS[lvl], "[scan %s/%s] %s", self.scan_id, self.stage, message)

    def debug(self, message: str) -> None:
        # Debug chatter is streamed but not persisted — it would dominate the table.
        self.log(message, level=LogLevel.DEBUG, persist=False)

    def warn(self, message: str) -> None:
        self.log(message, level=LogLevel.WARNING)

    def error(self, message: str) -> None:
        self.log(message, level=LogLevel.ERROR)

    # --- Structured events -------------------------------------------------

    def emit_result(self, kind: str, payload: Any) -> None:
        """Push a structured mid-scan result (new host, new finding, ...)."""
        publish(self.scan_id, result_event(self.scan_id, kind, payload))

    def emit_status(self, status: str, *, progress: int | None = None, **extra: Any) -> None:
        publish(
            self.scan_id,
            status_event(self.scan_id, status, stage=self.stage, progress=progress, **extra),
        )

    # --- Scan row updates --------------------------------------------------

    def set_stage(self, stage: str, progress: int) -> None:
        """Advance the scan to a new stage and tell subscribers."""
        self.stage = stage
        with session_scope() as session:
            scan = session.get(Scan, self.scan_id)
            if scan is not None:
                scan.current_stage = stage
                scan.progress = progress
        self.emit_status(ScanStatus.RUNNING.value, progress=progress)

    def bump_counters(self, *, assets: int = 0, findings: int = 0) -> None:
        if not assets and not findings:
            return
        with session_scope() as session:
            scan = session.get(Scan, self.scan_id)
            if scan is not None:
                scan.assets_discovered += assets
                scan.findings_count += findings

    def is_cancelled(self) -> bool:
        """Cooperative cancellation check.

        Modules call this between batches so a cancelled scan stops promptly
        even if the revoke signal did not land on this worker.
        """
        with session_scope() as session:
            status = session.scalar(select(Scan.status).where(Scan.id == self.scan_id))
        return status == ScanStatus.CANCELLED

    # --- Scope ------------------------------------------------------------

    def allowed_domains(self) -> list[str]:
        with session_scope() as session:
            org = session.get(Organisation, self.org_id)
            return org.all_domains if org else []


_LOGGING_LEVELS: dict[LogLevel, int] = {
    LogLevel.DEBUG: logging.DEBUG,
    LogLevel.INFO: logging.INFO,
    LogLevel.WARNING: logging.WARNING,
    LogLevel.ERROR: logging.ERROR,
}


class ScanCancelled(Exception):
    """Raised internally to unwind a cancelled scan."""


def chunked(items: Iterable[Any], size: int) -> Iterable[list[Any]]:
    batch: list[Any] = []
    for item in items:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def run_async(coro: Any) -> Any:
    """Run a coroutine to completion from synchronous task code.

    A Celery worker process has no running event loop, so ``asyncio.run`` is
    the right call there. It is not universally safe, though: under
    ``task_always_eager`` the task body executes inside whatever loop the
    caller is already on, and ``asyncio.run`` refuses to nest, so the stage
    dies with "cannot be called from a running event loop". Eager mode is a
    supported local-development configuration, so the stages must survive it.

    When a loop is already running we hand the coroutine to a private loop on a
    worker thread and block for the result. That is a little wasteful, but it
    only happens in the eager path, and the alternative is a scan that fails
    depending on how the process was started.
    """
    import asyncio

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


__all__ = ["ScanCancelled", "ScanContext", "chunked", "run_async"]
