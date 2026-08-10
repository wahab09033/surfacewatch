"""Report payloads."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from models.base import Severity

ReportFormat = Literal["pdf", "json", "csv"]


class ReportRequest(BaseModel):
    title: str | None = Field(default=None, max_length=255)
    format: ReportFormat = "pdf"
    scan_id: uuid.UUID | None = Field(
        default=None, description="Limit to one scan; omit for a full estate report"
    )
    min_severity: Severity = Severity.LOW
    include_info: bool = False
    include_remediated: bool = False


class ReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    org_id: uuid.UUID
    title: str | None
    format: str
    status: str
    file_path: str
    size_bytes: int | None
    summary: dict[str, Any]
    generated_at: datetime
    created_at: datetime


class DashboardOut(BaseModel):
    """Aggregate counters for the landing page."""

    assets_total: int
    assets_new_7d: int
    findings_open: int
    findings_by_severity: dict[str, int]
    scans_running: int
    scans_last_7d: int
    mean_risk_score: float
    top_risk_assets: list[dict[str, Any]]
    recent_findings: list[dict[str, Any]]
