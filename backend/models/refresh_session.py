"""Server-side refresh-token sessions with family-wide reuse detection.

A refresh token is a bearer credential, which means a stolen one is
indistinguishable from the real holder's. The standard defence is rotation: a
token is single-use, and re-presenting an already-rotated token is treated as
theft and kills the whole family. That detection needs server-side state, which
is what this table is.

``token_hash`` is SHA-256 of the raw token string, never the token itself —
the column is a database row an attacker with read access could dump, and a
stored raw refresh token would be a reusable credential exfiltrated wholesale.

``family_id`` groups the chain of rotated tokens that descend from one original
login. Reuse of any member revokes every row in the family: by the time a
stolen token is replayed, the legitimate holder has usually already rotated it
once, so the replay is almost always the attacker, and the correct response is
to kill the session for both sides.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.database import Base
from models.base import TimestampMixin, UUIDPk

if TYPE_CHECKING:
    from models.organisation import Organisation
    from models.user import User


def hash_refresh_token(token: str) -> str:
    """Deterministic fingerprint of a refresh token, safe to store."""
    import hashlib

    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class RefreshSession(Base, TimestampMixin):
    __tablename__ = "refresh_sessions"
    __table_args__ = (
        # One row per issued token. The hash is what the refresh endpoint looks
        # up, so it must be unique — a collision would let one token stand in
        # for another.
        UniqueConstraint("token_hash", name="uq_refresh_sessions_token_hash"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUIDPk, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUIDPk,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUIDPk,
        ForeignKey("organisations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # SHA-256 hex of the refresh token. Never the token itself.
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    # All rotated tokens descending from one login share this id. Reuse of any
    # member revokes every row in the family.
    family_id: Mapped[uuid.UUID] = mapped_column(
        UUIDPk, nullable=False, default=uuid.uuid4, index=True
    )

    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # The session this token was rotated into. NULL for the current head of the
    # chain and for revoked leaves (a revoked head keeps its replaced_by, so
    # the chain stays traceable for forensics).
    replaced_by: Mapped[uuid.UUID | None] = mapped_column(
        UUIDPk,
        ForeignKey("refresh_sessions.id", ondelete="SET NULL"),
        nullable=True,
    )
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    user: Mapped["User"] = relationship()
    organisation: Mapped["Organisation"] = relationship()

    @property
    def revoked(self) -> bool:
        return self.revoked_at is not None

    def __repr__(self) -> str:  # pragma: no cover
        state = "revoked" if self.revoked else "active"
        return f"<RefreshSession {self.family_id} {state}>"


__all__ = ["RefreshSession", "hash_refresh_token"]
