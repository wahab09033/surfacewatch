"""Scans and their streamed log lines."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import DateTime, Enum, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.database import Base
from models.base import LogLevel, ScanStatus, TimestampMixin, UUIDPk, utcnow

if TYPE_CHECKING:
    from models.finding import Finding
    from models.organisation import Organisation
    from models.user import User


class Scan(Base, TimestampMixin):
    __tablename__ = "scans"
    __table_args__ = (
        Index("ix_scans_org_started", "org_id", "started_at"),
        Index("ix_scans_org_status", "org_id", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUIDPk, primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUIDPk,
        ForeignKey("organisations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUIDPk, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    target: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, name="scan_status", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
        default=ScanStatus.QUEUED,
        server_default=ScanStatus.QUEUED.value,
    )

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # config: {"modules": ["subdomain_enum", "port_scanner", ...],
    #          "port_profile": "top-1000", "ports": [80,443],
    #          "passive_only": false, "max_subdomains": 500}
    config: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default="{}"
    )

    # Rolling counters so the UI can render progress without aggregating.
    current_stage: Mapped[str | None] = mapped_column(String(64), nullable=True)
    progress: Mapped[int] = mapped_column(nullable=False, default=0, server_default="0")
    assets_discovered: Mapped[int] = mapped_column(nullable=False, default=0, server_default="0")
    findings_count: Mapped[int] = mapped_column(nullable=False, default=0, server_default="0")

    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    celery_task_id: Mapped[str | None] = mapped_column(String(155), nullable=True, index=True)

    # --- Relationships -----------------------------------------------------
    organisation: Mapped["Organisation"] = relationship(back_populates="scans")
    author: Mapped["User | None"] = relationship()
    logs: Mapped[list["ScanLog"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="ScanLog.timestamp",
    )
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", passive_deletes=True
    )

    # --- Convenience -------------------------------------------------------
    @property
    def duration_seconds(self) -> float | None:
        if not self.started_at:
            return None
        end = self.completed_at or utcnow()
        return (end - self.started_at).total_seconds()

    @property
    def modules(self) -> list[str]:
        return list(self.config.get("modules") or [])

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Scan {self.target} {self.status.value}>"


class ScanLog(Base):
    """One streamed log line.

    Rows are persisted so a client connecting late (or reloading) can replay
    history before subscribing to the live Redis channel.
    """

    __tablename__ = "scan_logs"
    __table_args__ = (Index("ix_scan_logs_scan_ts", "scan_id", "timestamp"),)

    id: Mapped[uuid.UUID] = mapped_column(UUIDPk, primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUIDPk, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    message: Mapped[str] = mapped_column(Text, nullable=False)
    level: Mapped[LogLevel] = mapped_column(
        Enum(LogLevel, name="log_level", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
        default=LogLevel.INFO,
        server_default=LogLevel.INFO.value,
    )
    stage: Mapped[str | None] = mapped_column(String(64), nullable=True)

    scan: Mapped["Scan"] = relationship(back_populates="logs")

    def as_event(self) -> dict[str, Any]:
        """Serialise into the envelope pushed over Redis/WebSocket."""
        return {
            "type": "log",
            "scan_id": str(self.scan_id),
            "timestamp": self.timestamp.isoformat(),
            "level": self.level.value,
            "stage": self.stage,
            "message": self.message,
        }

    def __repr__(self) -> str:  # pragma: no cover
        return f"<ScanLog {self.level.value} {self.message[:40]!r}>"
