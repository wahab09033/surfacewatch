"""Findings — vulnerabilities and exposures attached to an asset."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import DateTime, Enum, Float, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.database import Base
from models.base import FindingStatus, Severity, TimestampMixin, UUIDPk

if TYPE_CHECKING:
    from models.asset import Asset
    from models.organisation import Organisation
    from models.scan import Scan


class Finding(Base, TimestampMixin):
    __tablename__ = "findings"
    __table_args__ = (
        # Re-running a scan must update the existing row rather than pile up
        # duplicates; ``fingerprint`` is the stable identity of an issue.
        UniqueConstraint("org_id", "fingerprint", name="uq_findings_org_fingerprint"),
        Index("ix_findings_org_severity", "org_id", "severity"),
        Index("ix_findings_org_status", "org_id", "status"),
        Index("ix_findings_org_cve", "org_id", "cve_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUIDPk, primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUIDPk,
        ForeignKey("organisations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDPk, ForeignKey("assets.id", ondelete="CASCADE"), nullable=True, index=True
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDPk, ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True
    )

    title: Mapped[str] = mapped_column(String(500), nullable=False)
    cve_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(128), nullable=True)
    severity: Mapped[Severity] = mapped_column(
        Enum(Severity, name="severity", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
        default=Severity.INFO,
        server_default=Severity.INFO.value,
    )

    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[FindingStatus] = mapped_column(
        Enum(FindingStatus, name="finding_status", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
        default=FindingStatus.OPEN,
        server_default=FindingStatus.OPEN.value,
    )

    # Which module raised it: cve_correlator, port_scanner, fingerprinter, ...
    source: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Stable dedupe key — see ``build_fingerprint``.
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)

    # Free-form supporting data: matched banner, request/response pair, CPE, ...
    evidence: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default="{}"
    )
    references: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default="[]"
    )

    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # --- Relationships -----------------------------------------------------
    organisation: Mapped["Organisation"] = relationship(back_populates="findings")
    asset: Mapped["Asset | None"] = relationship(back_populates="findings")
    scan: Mapped["Scan | None"] = relationship(back_populates="findings")

    # --- Helpers -----------------------------------------------------------
    @staticmethod
    def build_fingerprint(
        *, asset_id: uuid.UUID | str | None, title: str, cve_id: str | None = None,
        port: int | None = None,
    ) -> str:
        """Deterministic identity for a finding.

        Same asset + same issue => same fingerprint, so repeat scans update one
        row instead of creating a new one every night.
        """
        parts = [str(asset_id or "-"), (cve_id or title).strip().lower(), str(port or "-")]
        return hashlib.sha256("|".join(parts).encode()).hexdigest()

    @property
    def is_open(self) -> bool:
        return self.status in {FindingStatus.OPEN, FindingStatus.TRIAGED, FindingStatus.CONFIRMED}

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Finding {self.severity.value} {self.title[:50]!r}>"
