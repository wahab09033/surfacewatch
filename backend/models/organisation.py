"""Organisation — the tenant boundary for every other table."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, String, Text, true
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.database import Base
from models.base import TimestampMixin, UUIDPk

if TYPE_CHECKING:
    from models.asset import Asset
    from models.finding import Finding
    from models.report import Report
    from models.scan import Scan
    from models.user import User


class Organisation(Base, TimestampMixin):
    __tablename__ = "organisations"

    id: Mapped[uuid.UUID] = mapped_column(UUIDPk, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)

    # Primary domain. Scan targets are validated against this (plus
    # ``verified_domains``) so one tenant cannot point the scanner at another
    # party's infrastructure.
    domain: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    verified_domains: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default="[]"
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=true()
    )
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Incoming-webhook URL for critical-finding alerts. Nullable because
    # notifications are opt-in: no URL means no alerts, not a broken feature.
    #
    # This is a bearer credential — anyone holding the URL can post into the
    # channel — so it is never returned in full by the API. See
    # OrganisationRead.slack_webhook_configured / slack_webhook_hint.
    slack_webhook_url: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # --- Relationships -----------------------------------------------------
    users: Mapped[list["User"]] = relationship(
        back_populates="organisation", cascade="all, delete-orphan", passive_deletes=True
    )
    assets: Mapped[list["Asset"]] = relationship(
        back_populates="organisation", cascade="all, delete-orphan", passive_deletes=True
    )
    scans: Mapped[list["Scan"]] = relationship(
        back_populates="organisation", cascade="all, delete-orphan", passive_deletes=True
    )
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="organisation", cascade="all, delete-orphan", passive_deletes=True
    )
    reports: Mapped[list["Report"]] = relationship(
        back_populates="organisation", cascade="all, delete-orphan", passive_deletes=True
    )

    @property
    def all_domains(self) -> list[str]:
        """Primary domain plus any additional verified domains, de-duplicated."""
        domains = [self.domain, *(self.verified_domains or [])]
        seen: dict[str, None] = {}
        for d in domains:
            if d:
                seen.setdefault(d.lower().strip("."), None)
        return list(seen)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Organisation {self.name} ({self.domain})>"
