"""Shared column types, mixins and enums for the ORM models."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Index, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

# Reusable column type aliases -----------------------------------------------
UUIDPk = UUID(as_uuid=True)


def utcnow() -> datetime:
    """Timezone-aware UTC now (Python-side default)."""
    return datetime.now(timezone.utc)


def uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(UUIDPk, primary_key=True, default=uuid.uuid4)


class TimestampMixin:
    """Adds ``created_at`` / ``updated_at`` maintained by the database."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class OrgScopedMixin:
    """Every tenant-owned table carries an indexed ``org_id``.

    Deleting an organisation cascades to its data, and the index makes the
    mandatory ``WHERE org_id = :org`` filter cheap on every query.
    """

    @staticmethod
    def _org_fk() -> Mapped[uuid.UUID]:
        return mapped_column(
            UUIDPk,
            ForeignKey("organisations.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        )


# --- Enumerations -----------------------------------------------------------
# Stored as native Postgres enums; ``values_callable`` keeps the *values*
# (lower-case) in the DB rather than the Python member names.


class UserRole(str, enum.Enum):
    OWNER = "owner"
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"

    @property
    def rank(self) -> int:
        return _ROLE_RANK[self]

    def at_least(self, other: "UserRole") -> bool:
        return self.rank >= other.rank


_ROLE_RANK: dict[UserRole, int] = {
    UserRole.VIEWER: 0,
    UserRole.ANALYST: 1,
    UserRole.ADMIN: 2,
    UserRole.OWNER: 3,
}


class AssetStatus(str, enum.Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    NEW = "new"
    CHANGED = "changed"
    DECOMMISSIONED = "decommissioned"


class DomainVerificationStatus(str, enum.Enum):
    """Lifecycle of one organisation's claim on one domain.

    FAILED is not terminal: it records the last check's outcome so the UI can
    show *why* (wrong value, no record, DNS timeout) and the user can retry the
    same claim rather than deleting and re-adding it to get a fresh token.
    """

    PENDING = "pending"
    VERIFIED = "verified"
    FAILED = "failed"


class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

    @property
    def is_terminal(self) -> bool:
        return self in {ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED}


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_cvss(cls, score: float | None) -> "Severity":
        """Map a CVSS v3 base score onto its qualitative rating."""
        if score is None or score <= 0.0:
            return cls.INFO
        if score < 4.0:
            return cls.LOW
        if score < 7.0:
            return cls.MEDIUM
        if score < 9.0:
            return cls.HIGH
        return cls.CRITICAL

    @property
    def weight(self) -> float:
        return _SEVERITY_WEIGHT[self]


_SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.INFO: 0.0,
    Severity.LOW: 1.0,
    Severity.MEDIUM: 4.0,
    Severity.HIGH: 8.0,
    Severity.CRITICAL: 15.0,
}


class FindingStatus(str, enum.Enum):
    OPEN = "open"
    TRIAGED = "triaged"
    CONFIRMED = "confirmed"
    REMEDIATED = "remediated"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


class LogLevel(str, enum.Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


__all__ = [
    "AssetStatus",
    "DomainVerificationStatus",
    "FindingStatus",
    "Index",
    "JSONB",
    "LogLevel",
    "OrgScopedMixin",
    "ScanStatus",
    "Severity",
    "TimestampMixin",
    "UUIDPk",
    "UserRole",
    "utcnow",
    "uuid_pk",
]
