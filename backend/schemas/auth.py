"""Auth payloads."""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Any

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    field_validator,
    model_validator,
)

from core import passwords
from models.base import UserRole

_PASSWORD_MIN = passwords.MIN_LENGTH


def _validate_password(value: str, *, context: tuple[str, ...] = ()) -> str:
    """Reject weak passwords, including the ones a composition rule lets through.

    The previous version of this checked length plus "one letter, one digit",
    which is exactly the policy that accepts ``password1234``. The real test is
    whether other people have already chosen the same string, so the work now
    lives in core.passwords — see that module for why a bundled list is only
    half the answer.

    ``context`` is the account's own identifying strings; a password built from
    the email or organisation it protects is guessable by anyone looking at the
    login form.
    """
    problem = passwords.check(value, context=context)
    if problem is not None:
        raise ValueError(problem)
    return value


def _account_context(*values: str | None) -> tuple[str, ...]:
    """Identifying strings a password must not be derived from.

    An email is split on its local part and each domain label, because
    ``acme2024!`` for ``owner@acme.com`` is the pattern worth catching and the
    whole address would never match as one token. Hyphens are split too —
    ``acme-corp`` must yield ``acme``, not a single token that never matches
    anything a human would type. The password is compared against the
    *reduced* (alphabet-only) form, so a case-insensitive match here means the
    user typed a piece of their own identity.
    """
    tokens: list[str] = []
    for value in values:
        if not value:
            continue
        local, _, domain = value.partition("@")
        # Split the local part on any non-alphanumeric, then drop short junk.
        for piece in re.split(r"[^a-z0-9]+", local.lower()):
            if piece and len(piece) >= 3:
                tokens.append(piece)
        # Drop the public suffix: "com" and "co" are noise, not identity.
        tokens.extend(
            label for label in re.split(r"[^a-z0-9]+", domain.lower()) if len(label) > 3
        )
    return tuple(tokens)


class RegisterRequest(BaseModel):
    """Bootstraps a new organisation and its first (owner) user."""

    org_name: str = Field(min_length=2, max_length=255)
    domain: str = Field(min_length=3, max_length=253, description="Primary domain to monitor")
    email: EmailStr
    password: str
    full_name: str | None = Field(default=None, max_length=255)

    # A model validator, not a field validator: the password check needs the
    # email, org name and domain, and a field validator cannot see siblings.
    # mode="after" so it runs once every field is populated and normalised.
    @model_validator(mode="after")
    def _check_password(self) -> RegisterRequest:
        _validate_password(
            self.password,
            context=_account_context(self.email, self.org_name, self.domain, self.full_name),
        )
        return self

    @field_validator("domain")
    @classmethod
    def _normalise_domain(cls, v: str) -> str:
        # Deferred import so the rule lives in exactly one place. This used to be
        # a local copy that only checked for a dot, which let someone register
        # claiming an IP address or a bare public suffix like "co.uk" — and since
        # scope matching is by suffix, a verified "co.uk" would authorise every
        # domain under it.
        from core.domains import InvalidDomainError, normalise_claimable_domain

        try:
            return normalise_claimable_domain(v)
        except InvalidDomainError as exc:
            raise ValueError(str(exc)) from exc


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = Field(description="Access token lifetime in seconds")


class UserInvite(BaseModel):
    email: EmailStr
    password: str
    role: UserRole = UserRole.ANALYST
    full_name: str | None = Field(default=None, max_length=255)

    @model_validator(mode="after")
    def _check_password(self) -> UserInvite:
        _validate_password(
            self.password, context=_account_context(self.email, self.full_name)
        )
        return self


class PasswordChange(BaseModel):
    current_password: str
    new_password: str

    # No email on this payload, so there is no account context to check against
    # — the route knows the user, the schema does not.
    @model_validator(mode="after")
    def _check_password(self) -> PasswordChange:
        _validate_password(self.new_password)
        if self.new_password == self.current_password:
            raise ValueError("New password must be different from the current one")
        return self


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    org_id: uuid.UUID
    email: EmailStr
    full_name: str | None
    role: UserRole
    is_active: bool
    last_login_at: datetime | None
    created_at: datetime


class OrganisationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    domain: str
    verified_domains: list[str]
    created_at: datetime

    # The webhook URL itself is never serialised. It is a bearer credential:
    # whoever holds it can post into the customer's Slack channel, and an
    # endpoint that hands it back turns any read-only API token into the
    # ability to exfiltrate it. These two derived fields are everything the
    # settings UI actually needs — whether it is on, and enough of the path to
    # recognise which integration it is.
    slack_webhook_configured: bool = False
    slack_webhook_hint: str | None = None

    @classmethod
    def from_org(cls, org: Any) -> OrganisationOut:
        from workers.notifier import redact

        return cls(
            id=org.id,
            name=org.name,
            domain=org.domain,
            verified_domains=org.verified_domains or [],
            created_at=org.created_at,
            slack_webhook_configured=bool(org.slack_webhook_url),
            slack_webhook_hint=redact(org.slack_webhook_url),
        )


class SlackWebhookUpdate(BaseModel):
    """Set or clear the organisation's Slack incoming webhook.

    ``None`` clears it — explicitly rather than by sending an empty string, so
    "I did not touch this field" and "remove the integration" cannot be
    confused by a client that omits it.
    """

    webhook_url: str | None = Field(
        default=None,
        max_length=512,
        description=(
            "Slack incoming-webhook URL (https://hooks.slack.com/services/...). "
            "Send null to remove the integration."
        ),
    )

    @field_validator("webhook_url")
    @classmethod
    def _validate(cls, v: str | None) -> str | None:
        if v is None or not v.strip():
            return None
        # Same validator the worker uses before calling a stored URL, so the
        # rule cannot drift between where it is written and where it is used.
        from workers.notifier import InvalidWebhookURL, validate_webhook_url

        try:
            return validate_webhook_url(v)
        except InvalidWebhookURL as exc:
            raise ValueError(str(exc)) from exc
