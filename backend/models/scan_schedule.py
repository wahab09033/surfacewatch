"""Recurring scans: a saved target and config, plus when to run it next.

A ``Scan`` is one run; this is the standing instruction that produces runs. The
split matters because everything a schedule needs to fire is *denormalised* here
— target and config are copied, not referenced — so the dispatcher can queue a
scan without loading a scan's worth of related rows, and so editing a schedule
never rewrites the history of what already ran.

``next_run_at`` is the whole scheduling state. There is no queue of future runs
and no catch-up: the dispatcher advances this field and fires at most one scan
per due schedule per tick. A worker that was down for three hours produces one
scan, not three. Catching up would mean a tenant whose schedule sat due over a
weekend gets a burst of scans the moment the worker returns — the estate is
scanned repeatedly against a picture that was already stale, and the run that
matters (now) queues behind all of them.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    true,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.database import Base
from models.base import ScanCadence, TimestampMixin, UUIDPk, utcnow

if TYPE_CHECKING:
    from models.organisation import Organisation
    from models.scan import Scan
    from models.user import User


def next_occurrence(
    cadence: ScanCadence,
    hour_utc: int,
    weekday: int | None = None,
    *,
    after: datetime,
) -> datetime:
    """The first scheduled instant strictly after ``after``.

    ``after`` is a parameter rather than a call to ``utcnow()`` so this is a
    pure function of its inputs — the alternative is freezegun, or a test that
    can only assert "some time in the next hour", and neither pins the weekly
    weekday arithmetic that is the part most likely to be wrong.

    Strictly after, never equal: a schedule whose ``next_run_at`` is exactly
    ``after`` has already been fired by the tick that set it that way, and
    returning the same value again would make it fire twice.
    """
    if after.tzinfo is None:
        raise ValueError("after must be timezone-aware")
    # Everything is computed in UTC because ``hour_utc`` and ``weekday`` are
    # documented as UTC. A caller passing a local-time datetime would otherwise
    # get a schedule shifted by their offset, silently.
    after = after.astimezone(timezone.utc)

    if cadence is ScanCadence.HOURLY:
        # Top of the next hour. ``hour_utc`` is not consulted: an hourly
        # schedule that also pinned an hour would be a daily one.
        return after.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)

    if cadence is ScanCadence.DAILY:
        candidate = after.replace(hour=hour_utc, minute=0, second=0, microsecond=0)
        if candidate <= after:
            candidate += timedelta(days=1)
        return candidate

    if cadence is ScanCadence.WEEKLY:
        if weekday is None:
            raise ValueError("a weekly cadence needs a weekday")
        candidate = after.replace(hour=hour_utc, minute=0, second=0, microsecond=0)
        # Python's weekday(): Monday is 0. Shift forward to the next matching
        # day, which is today when it already matches — hence the second check,
        # because "today" at the configured hour may already have passed.
        candidate += timedelta(days=(weekday - candidate.weekday()) % 7)
        if candidate <= after:
            candidate += timedelta(days=7)
        return candidate

    raise ValueError(f"unsupported cadence {cadence!r}")  # pragma: no cover — enum is closed


class ScanSchedule(Base, TimestampMixin):
    __tablename__ = "scan_schedules"
    __table_args__ = (
        # The dispatcher's only query is "enabled and due". Leading with
        # is_enabled lets it seek straight to the due rows instead of scanning
        # every schedule in the table on every tick.
        Index("ix_scan_schedules_due", "is_enabled", "next_run_at"),
        # Enforced in the database as well as in the schema, because the column
        # is a bare SmallInteger and the dispatcher trusts it enough to pass it
        # to ``after.replace(hour=...)`` — a 25 stored by any path that skipped
        # validation would raise inside the scheduler, on every tick, forever.
        CheckConstraint("hour_utc BETWEEN 0 AND 23", name="ck_scan_schedules_hour_utc"),
        CheckConstraint(
            "weekday IS NULL OR weekday BETWEEN 0 AND 6",
            name="ck_scan_schedules_weekday",
        ),
        # A weekly schedule with no weekday is unrunnable, and the alternative
        # is discovering that inside the dispatcher at 3am.
        CheckConstraint(
            "cadence <> 'weekly' OR weekday IS NOT NULL",
            name="ck_scan_schedules_weekly_needs_weekday",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUIDPk, primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUIDPk,
        ForeignKey("organisations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # SET NULL, not CASCADE: an analyst leaving the company must not silently
    # delete the scans the organisation depends on. NULL here means "created by
    # a schedule", which is also what the Scan rows it produces carry.
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUIDPk, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    name: Mapped[str] = mapped_column(String(120), nullable=False)
    target: Mapped[str] = mapped_column(String(253), nullable=False)
    # Same shape as Scan.config — the same parser reads both.
    config: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default="{}"
    )

    cadence: Mapped[ScanCadence] = mapped_column(
        Enum(ScanCadence, name="scan_cadence", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
        default=ScanCadence.DAILY,
        server_default=ScanCadence.DAILY.value,
    )
    # Hour of day in UTC for DAILY and WEEKLY. Ignored by HOURLY, which runs on
    # the hour by definition.
    hour_utc: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, default=3, server_default="3"
    )
    # 0 = Monday, matching Python's weekday() and Postgres' ISODOW-1. Only set
    # for WEEKLY; NULL elsewhere.
    weekday: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)

    is_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=true()
    )
    next_run_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # SET NULL rather than CASCADE: retention may delete old scans, and losing
    # the run history must not take the schedule with it.
    last_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDPk, ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )

    # Consecutive broker/queue failures, reset on any successful dispatch.
    consecutive_failures: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    # Why the schedule switched itself off — a revoked domain and an
    # unreachable broker are both "disabled", and only one of them is the
    # customer's to fix. Rendered verbatim in the UI.
    disabled_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    # --- Relationships -----------------------------------------------------
    organisation: Mapped["Organisation"] = relationship(back_populates="scan_schedules")
    author: Mapped["User | None"] = relationship()
    last_scan: Mapped["Scan | None"] = relationship()

    # --- Convenience -------------------------------------------------------
    @property
    def is_weekly(self) -> bool:
        return self.cadence is ScanCadence.WEEKLY

    def advance(self, *, after: datetime | None = None) -> datetime:
        """Move ``next_run_at`` past ``after`` and return the new value."""
        moment = after or self.next_run_at
        self.next_run_at = next_occurrence(
            self.cadence, self.hour_utc, self.weekday, after=moment
        )
        return self.next_run_at

    def describe(self) -> str:
        """Human-readable cadence, for the UI and log lines."""
        days = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
        if self.cadence is ScanCadence.HOURLY:
            return "every hour"
        if self.cadence is ScanCadence.DAILY:
            return f"every day at {self.hour_utc:02d}:00 UTC"
        if self.weekday is None:  # pragma: no cover — the check constraint forbids it
            return f"weekly at {self.hour_utc:02d}:00 UTC"
        return f"every {days[self.weekday]} at {self.hour_utc:02d}:00 UTC"

    def __repr__(self) -> str:  # pragma: no cover
        state = "enabled" if self.is_enabled else "disabled"
        return f"<ScanSchedule {self.name!r} {self.target} {self.cadence.value} {state}>"


def initial_next_run(
    cadence: ScanCadence, hour_utc: int, weekday: int | None, *, now: datetime | None = None
) -> datetime:
    """``next_run_at`` for a schedule that has never run.

    Created schedules must not be due immediately. A schedule saved at 14:00
    for "daily at 03:00" should first fire tomorrow morning — firing it the
    moment it is saved means the act of configuring a recurring scan kicks off
    a scan, which is a surprise, and it makes the feature unusable on a large
    estate where the user is still editing.
    """
    return next_occurrence(cadence, hour_utc, weekday, after=now or utcnow())


__all__ = ["ScanSchedule", "initial_next_run", "next_occurrence"]
