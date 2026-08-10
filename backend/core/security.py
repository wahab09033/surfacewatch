"""Password hashing and JWT issuing/validation.

bcrypt is used directly rather than through passlib, which has an unresolved
incompatibility with bcrypt >= 4.1.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

import bcrypt
import jwt
from jwt.exceptions import InvalidTokenError

from config import settings

# bcrypt only considers the first 72 bytes of input and (in 4.x) raises on
# longer values. Pre-hashing would change the stored format, so we truncate at
# the byte boundary instead and document it.
_BCRYPT_MAX_BYTES = 72

TokenType = Literal["access", "refresh"]


# --- Passwords --------------------------------------------------------------


def _prepare(password: str) -> bytes:
    return password.encode("utf-8")[:_BCRYPT_MAX_BYTES]


def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=settings.bcrypt_rounds)
    return bcrypt.hashpw(_prepare(password), salt).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Constant-time comparison; returns False on any malformed hash."""
    try:
        return bcrypt.checkpw(_prepare(password), password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


# --- Tokens -----------------------------------------------------------------


def _create_token(
    *,
    user_id: uuid.UUID,
    org_id: uuid.UUID,
    role: str,
    token_version: int,
    token_type: TokenType,
    expires_delta: timedelta,
) -> str:
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": str(user_id),
        # org_id travels in the token so every request is scoped without an
        # extra lookup — but it is still re-checked against the DB row.
        "org_id": str(org_id),
        "role": role,
        "tv": token_version,
        "type": token_type,
        "iat": int(now.timestamp()),
        "exp": int((now + expires_delta).timestamp()),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def create_access_token(
    *, user_id: uuid.UUID, org_id: uuid.UUID, role: str, token_version: int = 0
) -> str:
    return _create_token(
        user_id=user_id,
        org_id=org_id,
        role=role,
        token_version=token_version,
        token_type="access",
        expires_delta=timedelta(minutes=settings.access_token_expire_minutes),
    )


def create_refresh_token(
    *, user_id: uuid.UUID, org_id: uuid.UUID, role: str, token_version: int = 0
) -> str:
    return _create_token(
        user_id=user_id,
        org_id=org_id,
        role=role,
        token_version=token_version,
        token_type="refresh",
        expires_delta=timedelta(days=settings.refresh_token_expire_days),
    )


class TokenPayload:
    """Validated JWT claims."""

    __slots__ = ("user_id", "org_id", "role", "token_version", "token_type", "jti", "exp")

    def __init__(self, claims: dict[str, Any]) -> None:
        self.user_id = uuid.UUID(claims["sub"])
        self.org_id = uuid.UUID(claims["org_id"])
        self.role: str = claims["role"]
        self.token_version: int = int(claims.get("tv", 0))
        self.token_type: str = claims.get("type", "access")
        self.jti: str | None = claims.get("jti")
        self.exp: int = int(claims["exp"])


def decode_token(token: str, *, expect: TokenType = "access") -> TokenPayload:
    """Decode and validate a JWT.

    Raises ``InvalidTokenError`` on a bad signature, expiry, missing claims, or
    a token of the wrong type (a refresh token cannot authenticate a request).
    """
    claims = jwt.decode(
        token,
        settings.jwt_secret,
        algorithms=[settings.jwt_algorithm],
        options={"require": ["exp", "sub", "iat"]},
    )
    if claims.get("type") != expect:
        raise InvalidTokenError(f"expected a {expect} token, got {claims.get('type')!r}")
    if "org_id" not in claims:
        raise InvalidTokenError("token is missing the org_id claim")
    try:
        return TokenPayload(claims)
    except (KeyError, ValueError) as exc:
        raise InvalidTokenError(f"malformed claims: {exc}") from exc


__all__ = [
    "InvalidTokenError",
    "TokenPayload",
    "create_access_token",
    "create_refresh_token",
    "decode_token",
    "hash_password",
    "verify_password",
]
