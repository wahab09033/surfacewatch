"""Asset payloads."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.scoring import normalise_host
from models.base import AssetStatus


class PortEntry(BaseModel):
    port: int = Field(ge=1, le=65535)
    protocol: str = "tcp"
    state: str = "open"
    service: str | None = None
    banner: str | None = None


class TechEntry(BaseModel):
    name: str
    version: str | None = None
    categories: list[str] = Field(default_factory=list)
    confidence: int = Field(default=50, ge=0, le=100)
    cpe: str | None = None


class AssetCreate(BaseModel):
    hostname: str = Field(min_length=1, max_length=253)
    ip: str | None = Field(default=None, max_length=45)
    notes: str | None = None

    @field_validator("hostname")
    @classmethod
    def _clean(cls, v: str) -> str:
        host = normalise_host(v)
        if not host:
            raise ValueError("Invalid hostname")
        return host


class AssetUpdate(BaseModel):
    ip: str | None = Field(default=None, max_length=45)
    status: AssetStatus | None = None
    notes: str | None = None


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    org_id: uuid.UUID
    hostname: str
    ip: str | None
    ports: list[dict[str, Any]]
    tech_stack: list[dict[str, Any]]
    risk_score: float
    last_scanned: datetime | None
    status: AssetStatus
    discovery_source: str | None
    first_seen: datetime | None
    notes: str | None
    created_at: datetime


class AssetSummary(BaseModel):
    """Lightweight row for tables and the dashboard."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    hostname: str
    ip: str | None
    risk_score: float
    status: AssetStatus
    last_scanned: datetime | None
    open_port_count: int = 0
    finding_count: int = 0


class AssetStatsOut(BaseModel):
    total: int
    by_status: dict[str, int]
    highest_risk: list[AssetSummary]
    newly_discovered_7d: int


# --- Blast radius graph -----------------------------------------------------


class GraphNode(BaseModel):
    """One node in the blast radius map.

    ``risk_score`` is 0-100 on every node type, including the derived ones, so
    the client has a single colour path. The frontend bands it with
    ``riskBand()`` in lib/format.ts — the thresholds deliberately live there and
    only there, because a node coloured differently from the same asset's row
    in the table is worse than either colour being slightly off.
    """

    id: str
    label: str
    kind: Literal["domain", "subdomain", "ip", "port"]
    risk_score: float = 0.0

    # Set only on ``subdomain`` nodes: the real asset id, which is what the
    # click handler passes to the AssetDrawer. Other node kinds are structural
    # and have nothing to open.
    asset_id: uuid.UUID | None = None

    finding_count: int = 0
    open_port_count: int = 0

    # On an ``ip`` node: how many subdomains resolve here. This is the number
    # the map exists to make visible — one host carrying eight names means
    # compromising it costs you eight names.
    shared_by: int = 0

    # On a ``port`` node: the service banner-derived name, when known.
    service: str | None = None


class GraphLink(BaseModel):
    source: str
    target: str


class GraphOut(BaseModel):
    nodes: list[GraphNode]
    links: list[GraphLink]

    total_assets: int
    # True when the estate was too large to render in full. The client says so
    # rather than silently showing a partial map that looks complete — an ASM
    # operator drawing conclusions about coverage from a truncated graph is a
    # worse outcome than an ugly banner.
    truncated: bool = False
    truncated_reason: str | None = None
