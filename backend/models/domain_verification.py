"""Proof-of-ownership claims on the domains an organisation may scan.

``Organisation.verified_domains`` is the fast path — ``assert_in_scope`` reads it
on every scan create, every asset create, and inside every worker — but it is
only a list of strings, with nowhere to put a challenge token, a pending state,
or why the last check failed. This table holds that per-domain state and is the
record of truth; ``verified_domains`` is a denormalised cache of the rows here
whose status is VERIFIED.

**The two must be written in the same transaction.** A row marked VERIFIED whose
domain never reached ``verified_domains`` is an org that proved ownership and
still cannot scan; the reverse is a domain that is scannable without proof, which
is the hole this table exists to close.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Enum, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.database import Base
from models.base import DomainVerificationStatus, TimestampMixin, UUIDPk, utcnow

if TYPE_CHECKING:
    from models.organisation import Organisation
    from models.user import User


# The DNS label the challenge record lives under. Leading underscore so it can
# never collide with a real hostname, following the _acme-challenge convention
# users already recognise from Let's Encrypt.
CHALLENGE_LABEL = "_surfacewatch-challenge"

# Accepted on the apex as a fallback, for DNS panels that make underscore labels
# awkward. The value has to be self-identifying there because the apex TXT RRset
# is shared with SPF/DKIM/DMARC and every other vendor's verification string;
# under our own label it does not, so the bare token is enough.
APEX_PREFIX = "surfacewatch-verification="

# 32 bytes of entropy -> 43 URL-safe characters. The token is a bearer secret in
# the weak sense that anyone who can read it and write DNS for the domain can
# verify it — but writing DNS for the domain *is* the thing being proven, so
# disclosure alone grants nothing.
_TOKEN_BYTES = 32

# How long a challenge token stays valid. Verification must be a windowed
# proof: a token that never expired could be published years later by someone
# who obtained it once, and an expired token forces the user to publish a fresh
# value, which only the current DNS owner can do. A week is long enough that a
# DNS panel that batches changes or a user on holiday is not locked out, short
# enough that a leaked token decays on its own.
TOKEN_TTL = timedelta(days=7)


def new_token() -> str:
    """Generate a fresh challenge value."""
    return secrets.token_urlsafe(_TOKEN_BYTES)


class DomainVerification(Base, TimestampMixin):
    __tablename__ = "domain_verifications"
    __table_args__ = (
        # One claim per (org, domain). Re-adding a domain reuses this row and its
        # token rather than minting a second challenge, which would silently
        # invalidate the TXT record the user already published.
        UniqueConstraint("org_id", "domain", name="uq_domain_verifications_org_domain"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUIDPk, primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUIDPk,
        ForeignKey("organisations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # Nullable with SET NULL: deleting the admin who added a domain must not
    # revoke the organisation's proof of ownership.
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUIDPk, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    domain: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    token: Mapped[str] = mapped_column(String(64), nullable=False, default=new_token)
    # When ``token`` stops being acceptable proof. Checked on every verify
    # attempt; an expired token is rotated to a fresh one so the user can
    # publish the new value without deleting and re-adding the claim.
    token_expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: utcnow() + TOKEN_TTL,
    )

    status: Mapped[DomainVerificationStatus] = mapped_column(
        Enum(
            DomainVerificationStatus,
            name="domain_verification_status",
            values_callable=lambda e: [m.value for m in e],
        ),
        nullable=False,
        default=DomainVerificationStatus.PENDING,
        server_default=DomainVerificationStatus.PENDING.value,
    )

    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_checked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Shown verbatim in the settings UI. "No TXT record found" and "record found
    # but the value did not match" send users to different places in their DNS
    # panel, so the distinction is worth persisting.
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Only consulted by the weekly re-verification task. A single failed check is
    # far more likely to be a DNS blip than a domain changing hands, so
    # revocation waits for several in a row.
    consecutive_failures: Mapped[int] = mapped_column(
        nullable=False, default=0, server_default="0"
    )

    # --- Relationships -----------------------------------------------------
    organisation: Mapped["Organisation"] = relationship(back_populates="domain_verifications")
    author: Mapped["User | None"] = relationship()

    # --- Convenience -------------------------------------------------------
    @property
    def record_name(self) -> str:
        """Fully-qualified name of the TXT record the user must create."""
        return f"{CHALLENGE_LABEL}.{self.domain}"

    @property
    def apex_record_value(self) -> str:
        """The value to use if publishing on the apex instead of ``record_name``."""
        return f"{APEX_PREFIX}{self.token}"

    @property
    def is_verified(self) -> bool:
        return self.status is DomainVerificationStatus.VERIFIED

    def __repr__(self) -> str:  # pragma: no cover
        return f"<DomainVerification {self.domain} {self.status.value}>"
