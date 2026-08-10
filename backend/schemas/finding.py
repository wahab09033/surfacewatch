"""Finding payloads."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from models.base import FindingStatus, Severity


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    org_id: uuid.UUID
    asset_id: uuid.UUID | None
    scan_id: uuid.UUID | None
    title: str
    cve_id: str | None
    cvss_score: float | None
    cvss_vector: str | None
    severity: Severity
    description: str | None
    remediation: str | None
    status: FindingStatus
    source: str | None
    evidence: dict[str, Any]
    references: list[str]
    first_seen: datetime | None
    last_seen: datetime | None
    resolved_at: datetime | None
    created_at: datetime

    # Denormalised for list views so the client does not need a second call.
    asset_hostname: str | None = None


class FindingUpdate(BaseModel):
    """Triage actions. Analysts change status and can override severity."""

    status: FindingStatus | None = None
    severity: Severity | None = None
    remediation: str | None = None
    notes: str | None = Field(default=None, max_length=4000)


class FindingCreate(BaseModel):
    """Manual finding entry — for issues discovered by hand during an engagement."""

    asset_id: uuid.UUID | None = None
    title: str = Field(min_length=3, max_length=500)
    cve_id: str | None = Field(default=None, max_length=32)
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    severity: Severity | None = None
    description: str | None = None
    remediation: str | None = None
    references: list[str] = Field(default_factory=list)


class FindingStatsOut(BaseModel):
    total: int
    open: int
    by_severity: dict[str, int]
    by_status: dict[str, int]
    top_cves: list[dict[str, Any]] = Field(
        default_factory=list, description="Most frequent CVEs across the estate"
    )
    mean_cvss: float | None = None
