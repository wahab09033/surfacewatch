"""User accounts. Email is unique per organisation, not globally."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, String, UniqueConstraint, true
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.database import Base
from models.base import TimestampMixin, UserRole, UUIDPk

if TYPE_CHECKING:
    from models.organisation import Organisation


class User(Base, TimestampMixin):
    __tablename__ = "users"
    __table_args__ = (
        # Same person can hold accounts in two tenants; within one tenant the
        # address must be unique.
        UniqueConstraint("org_id", "email", name="uq_users_org_email"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUIDPk, primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUIDPk,
        ForeignKey("organisations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    email: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    full_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole, name="user_role", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
        default=UserRole.ANALYST,
        server_default="analyst",
    )

    # bcrypt hash — never the plaintext, never reversible.
    password_hash: Mapped[str] = mapped_column(String(128), nullable=False)

    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=true()
    )
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Bumped on password change / forced logout; embedded in issued JWTs so
    # outstanding tokens stop validating.
    token_version: Mapped[int] = mapped_column(
        nullable=False, default=0, server_default="0"
    )

    organisation: Mapped["Organisation"] = relationship(back_populates="users")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<User {self.email} role={self.role.value}>"
