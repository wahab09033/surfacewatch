"""Scan payloads."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.scoring import normalise_host
from models.base import LogLevel, ScanStatus

# Module identifiers map 1:1 onto the Celery tasks in ``workers/``.
ScanModule = Literal[
    "subdomain_enum",
    "port_scanner",
    "fingerprinter",
    "cve_correlator",
    "change_detector",
]

ALL_MODULES: tuple[ScanModule, ...] = (
    "subdomain_enum",
    "port_scanner",
    "fingerprinter",
    "cve_correlator",
    "change_detector",
)

PortProfile = Literal["top-100", "top-1000", "web", "full", "custom"]


class ScanConfig(BaseModel):
    """Per-scan tuning, persisted to ``scans.config``."""

    modules: list[ScanModule] = Field(default_factory=lambda: list(ALL_MODULES))
    port_profile: PortProfile = "top-1000"
    ports: list[int] = Field(
        default_factory=list, description="Explicit port list when port_profile is 'custom'"
    )
    max_subdomains: int = Field(default=500, ge=1, le=10_000)
    passive_only: bool = Field(
        default=False,
        description="Skip anything that sends traffic to the target (DNS/CT only)",
    )
    connect_timeout: float = Field(default=2.0, gt=0, le=30)
    rate_limit: int = Field(
        default=50, ge=1, le=1000, description="Max concurrent connections per host"
    )
    include_wildcards: bool = False

    @field_validator("modules")
    @classmethod
    def _dedupe(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("Select at least one scan module")
        # Preserve pipeline order rather than the client's order — later stages
        # consume earlier output.
        return [m for m in ALL_MODULES if m in set(v)]

    @field_validator("ports")
    @classmethod
    def _validate_ports(cls, v: list[int]) -> list[int]:
        for p in v:
            if not 1 <= p <= 65535:
                raise ValueError(f"Invalid port: {p}")
        return sorted(set(v))


class ScanCreate(BaseModel):
    target: str = Field(min_length=3, max_length=253)
    config: ScanConfig = Field(default_factory=ScanConfig)

    @field_validator("target")
    @classmethod
    def _clean(cls, v: str) -> str:
        host = normalise_host(v)
        if not host or "." not in host:
            raise ValueError("Enter a fully-qualified host or domain, e.g. example.com")
        return host


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    org_id: uuid.UUID
    target: str
    status: ScanStatus
    started_at: datetime | None
    completed_at: datetime | None
    config: dict[str, Any]
    current_stage: str | None
    progress: int
    assets_discovered: int
    findings_count: int
    error: str | None
    created_at: datetime
    duration_seconds: float | None = None


class ScanLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    timestamp: datetime
    message: str
    level: LogLevel
    stage: str | None
