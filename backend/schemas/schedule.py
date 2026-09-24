"""Scheduled-scan payloads."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from core.scoring import normalise_host
from models.base import ScanCadence
from schemas.scan import ScanConfig

# 0 = Monday, matching ScanSchedule.weekday and Python's date.weekday().
WEEKDAY_NAMES: tuple[str, ...] = (
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
    "Sunday",
)


class ScheduleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    target: str = Field(min_length=3, max_length=253)
    config: ScanConfig = Field(default_factory=ScanConfig)
    cadence: ScanCadence = ScanCadence.DAILY
    hour_utc: int = Field(default=3, ge=0, le=23)
    weekday: int | None = Field(default=None, ge=0, le=6)

    @field_validator("name")
    @classmethod
    def _clean_name(cls, v: str) -> str:
        name = v.strip()
        if not name:
            raise ValueError("Give the schedule a name")
        return name

    @field_validator("target")
    @classmethod
    def _clean_target(cls, v: str) -> str:
        host = normalise_host(v)
        if not host or "." not in host:
            raise ValueError("Enter a fully-qualified host or domain, e.g. example.com")
        return host

    @model_validator(mode="after")
    def _cadence_consistency(self) -> ScheduleCreate:
        """Reject combinations the scheduler cannot act on.

        The database enforces the weekly-needs-weekday rule too, but a 500 from
        a check constraint is not an error message anyone can act on, and this is
        the layer that knows how to say which field is wrong.

        ``weekday`` is *cleared* for non-weekly cadences rather than rejected.
        A user switching weekly -> daily leaves the old weekday in the form, and
        failing the save for a field the chosen cadence does not display is a
        dead end.
        """
        if self.cadence is ScanCadence.WEEKLY:
            if self.weekday is None:
                raise ValueError("Choose a day of the week for a weekly schedule")
        else:
            self.weekday = None
        return self


class ScheduleUpdate(BaseModel):
    """Partial update. Every field is optional; absent means unchanged."""

    name: str | None = Field(default=None, min_length=1, max_length=120)
    config: ScanConfig | None = None
    cadence: ScanCadence | None = None
    hour_utc: int | None = Field(default=None, ge=0, le=23)
    weekday: int | None = Field(default=None, ge=0, le=6)
    is_enabled: bool | None = None

    @field_validator("name")
    @classmethod
    def _clean_name(cls, v: str | None) -> str | None:
        if v is None:
            return None
        name = v.strip()
        if not name:
            raise ValueError("Give the schedule a name")
        return name

    # The target is deliberately NOT updatable. Changing it would silently
    # repoint a recurring scan at a different host, and the schedule would carry
    # on producing scans against a target whose authorisation was never checked
    # for it. Deleting and re-creating makes that a deliberate act.


class ScheduleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    org_id: uuid.UUID
    name: str
    target: str
    config: dict
    cadence: ScanCadence
    hour_utc: int
    weekday: int | None
    is_enabled: bool
    next_run_at: datetime
    last_run_at: datetime | None
    last_scan_id: uuid.UUID | None
    consecutive_failures: int
    # Populated when the scheduler switched this off by itself. The UI shows it
    # verbatim: an autodisabled schedule with no explanation reads as a bug.
    disabled_reason: str | None
    created_at: datetime

    # Computed for display so the frontend does not re-implement cadence
    # formatting, and so "every Monday at 03:00 UTC" is worded once.
    schedule_text: str | None = None

    @classmethod
    def from_row(cls, row) -> ScheduleOut:
        out = cls.model_validate(row)
        out.schedule_text = row.describe()
        return out


class ScheduleList(BaseModel):
    items: list[ScheduleOut]
