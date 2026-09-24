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
    from models.domain_verification import DomainVerification
    from models.finding import Finding
    from models.report import Report
    from models.scan import Scan
    from models.scan_schedule import ScanSchedule
    from models.user import User


class Organisation(Base, TimestampMixin):
    __tablename__ = "organisations"

    id: Mapped[uuid.UUID] = mapped_column(UUIDPk, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)

    # The organisation's stated primary domain, used for display and as the
    # domain we pre-create a verification challenge for at registration.
    #
    # It grants NO scanning authority on its own. It is free text from the
    # registration form, and registration is open to the public, so trusting it
    # would let anyone sign up claiming a domain they do not own and scan it.
    # ``all_domains`` reads ``verified_domains`` only.
    domain: Mapped[str] = mapped_column(String(253), nullable=False, index=True)

    # Domains this org has proven control of, via a DNS TXT challenge. This is
    # the authorisation list every scope check reads, and the only way in is
    # models.DomainVerification reaching VERIFIED — see that model's docstring
    # for why the two are kept in sync inside one transaction.
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
    domain_verifications: Mapped[list["DomainVerification"]] = relationship(
        back_populates="organisation", cascade="all, delete-orphan", passive_deletes=True
    )
    scan_schedules: Mapped[list["ScanSchedule"]] = relationship(
        back_populates="organisation", cascade="all, delete-orphan", passive_deletes=True
    )

    @property
    def all_domains(self) -> list[str]:
        """Every domain this organisation is authorised to scan, de-duplicated.

        Only verified domains. ``self.domain`` is deliberately NOT included: it
        comes straight from the registration form, and with public registration
        including it would mean anyone could sign up claiming ``microsoft.com``
        and legitimately port-scan it. Proof of ownership is the only way a
        domain reaches ``verified_domains``.

        An empty list is a valid state — a freshly registered org that has not
        completed its DNS challenge can scan nothing, and every caller must cope
        with that rather than falling back to ``self.domain``.
        """
        seen: dict[str, None] = {}
        for d in self.verified_domains or []:
            if d:
                seen.setdefault(d.lower().strip("."), None)
        return list(seen)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Organisation {self.name} ({self.domain})>"
