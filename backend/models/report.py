"""Generated report artefacts (PDF / JSON exports)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import DateTime, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.database import Base
from models.base import TimestampMixin, UUIDPk, utcnow

if TYPE_CHECKING:
    from models.organisation import Organisation
    from models.user import User


class Report(Base, TimestampMixin):
    __tablename__ = "reports"
    __table_args__ = (Index("ix_reports_org_generated", "org_id", "generated_at"),)

    id: Mapped[uuid.UUID] = mapped_column(UUIDPk, primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUIDPk,
        ForeignKey("organisations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    generated_by: Mapped[uuid.UUID | None] = mapped_column(
        UUIDPk, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    # Path on the shared volume. Downloads always go through the API so the
    # org check is enforced — the path is never exposed directly.
    file_path: Mapped[str] = mapped_column(String(1024), nullable=False)

    title: Mapped[str | None] = mapped_column(String(255), nullable=True)
    format: Mapped[str] = mapped_column(
        String(16), nullable=False, default="pdf", server_default="pdf"
    )
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="pending", server_default="pending"
    )
    size_bytes: Mapped[int | None] = mapped_column(nullable=True)

    # Snapshot of counts at generation time + the filters used.
    summary: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default="{}"
    )

    organisation: Mapped["Organisation"] = relationship(back_populates="reports")
    author: Mapped["User | None"] = relationship()

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Report {self.file_path} {self.status}>"
