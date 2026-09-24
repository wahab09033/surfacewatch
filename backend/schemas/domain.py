"""Domain-verification payloads."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from models.base import DomainVerificationStatus


class DomainAdd(BaseModel):
    """Claim a domain. Verification is a separate, explicit step."""

    domain: str = Field(min_length=3, max_length=253)

    @field_validator("domain")
    @classmethod
    def _normalise(cls, v: str) -> str:
        # Imported here rather than at module scope so the rule has exactly one
        # home (core.domains) and this schema cannot drift from the route or from
        # RegisterRequest — the same reasoning as SlackWebhookUpdate deferring to
        # workers.notifier.validate_webhook_url.
        from core.domains import InvalidDomainError, normalise_claimable_domain

        try:
            return normalise_claimable_domain(v)
        except InvalidDomainError as exc:
            raise ValueError(str(exc)) from exc


class DomainVerificationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    domain: str
    status: DomainVerificationStatus
    verified_at: datetime | None
    last_checked_at: datetime | None
    last_error: str | None
    created_at: datetime

    # Everything the user needs to publish the record, computed server-side so the
    # frontend never has to know the challenge format. Both are returned for
    # unverified claims and suppressed once verified — the record still has to
    # stay published for re-verification, but showing a token nobody needs to act
    # on is noise.
    record_name: str | None = None
    record_value: str | None = None
    apex_record_name: str | None = None
    apex_record_value: str | None = None

    @classmethod
    def from_row(cls, row: Any) -> DomainVerificationOut:
        """Build from a DomainVerification, attaching DNS instructions.

        An explicit constructor rather than plain ``from_attributes``: the four
        record fields are derived, and a field added to this schema without being
        set here would silently serialise as null.
        """
        pending = not row.is_verified
        return cls(
            id=row.id,
            domain=row.domain,
            status=row.status,
            verified_at=row.verified_at,
            last_checked_at=row.last_checked_at,
            last_error=row.last_error,
            created_at=row.created_at,
            record_name=row.record_name if pending else None,
            record_value=row.token if pending else None,
            apex_record_name=row.domain if pending else None,
            apex_record_value=row.apex_record_value if pending else None,
        )


class DomainVerificationList(BaseModel):
    items: list[DomainVerificationOut]
    # Surfaced so the UI can render "3 of 25 used" without hardcoding the cap,
    # and so it can disable the add button rather than letting the POST 409.
    limit: int = Field(description="Maximum domains this organisation may hold")


class DomainVerifyResult(BaseModel):
    """Outcome of a verification attempt."""

    verified: bool
    verification: DomainVerificationOut
    # Present when verified is False. The DNS layer distinguishes "no record",
    # "wrong value" and "lookup failed", because those send the user to three
    # different places.
    detail: str | None = None
