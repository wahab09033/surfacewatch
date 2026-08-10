"""Assets — the hosts that make up an organisation's attack surface."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import DateTime, Enum, Float, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.database import Base
from models.base import AssetStatus, TimestampMixin, UUIDPk

if TYPE_CHECKING:
    from models.finding import Finding
    from models.organisation import Organisation


class Asset(Base, TimestampMixin):
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("org_id", "hostname", name="uq_assets_org_hostname"),
        # Supports the dashboard's "riskiest assets in my org" query.
        Index("ix_assets_org_risk", "org_id", "risk_score"),
        Index("ix_assets_org_status", "org_id", "status"),
        # GIN indexes make containment queries over the JSONB payloads usable,
        # e.g. "which assets expose port 22" or "which run nginx".
        Index("ix_assets_ports_gin", "ports", postgresql_using="gin"),
        Index("ix_assets_tech_gin", "tech_stack", postgresql_using="gin"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUIDPk, primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUIDPk,
        ForeignKey("organisations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    hostname: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)

    # ports: [{"port": 443, "protocol": "tcp", "state": "open",
    #           "service": "https", "banner": "nginx/1.24.0"}]
    ports: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list, server_default="[]"
    )

    # tech_stack: [{"name": "nginx", "version": "1.24.0", "categories": ["web-server"],
    #               "confidence": 90, "cpe": "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"}]
    tech_stack: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list, server_default="[]"
    )

    risk_score: Mapped[float] = mapped_column(
        Float, nullable=False, default=0.0, server_default="0"
    )
    last_scanned: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    status: Mapped[AssetStatus] = mapped_column(
        Enum(AssetStatus, name="asset_status", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
        default=AssetStatus.NEW,
        server_default=AssetStatus.NEW.value,
    )

    # Provenance: how this asset was found ("subdomain_enum", "manual", "import").
    discovery_source: Mapped[str | None] = mapped_column(String(64), nullable=True)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # --- Relationships -----------------------------------------------------
    organisation: Mapped["Organisation"] = relationship(back_populates="assets")
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="asset", cascade="all, delete-orphan", passive_deletes=True
    )

    # --- Convenience -------------------------------------------------------
    @property
    def open_ports(self) -> list[int]:
        return sorted(
            p["port"] for p in (self.ports or []) if p.get("state") == "open" and "port" in p
        )

    @property
    def technologies(self) -> list[str]:
        return sorted({t["name"] for t in (self.tech_stack or []) if t.get("name")})

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Asset {self.hostname} risk={self.risk_score:.1f}>"
