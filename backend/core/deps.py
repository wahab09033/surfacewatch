"""Shared FastAPI dependencies.

The org-isolation contract lives here: route handlers never receive a raw
``org_id`` from the client. They receive a ``CurrentUser`` whose ``org_id``
came from a signed token and was re-verified against the database row, and
every query filters on it.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, Query, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.security import InvalidTokenError, decode_token
from db.database import AsyncSessionLocal, get_db
from models import User, UserRole

_bearer = HTTPBearer(auto_error=False, description="JWT access token")

_UNAUTHENTICATED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Not authenticated",
    headers={"WWW-Authenticate": "Bearer"},
)


@dataclass(frozen=True, slots=True)
class CurrentUser:
    """Authenticated principal. ``org_id`` is the tenant scope for all queries."""

    id: uuid.UUID
    org_id: uuid.UUID
    email: str
    role: UserRole

    def require_role(self, minimum: UserRole) -> None:
        if not self.role.at_least(minimum):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires {minimum.value} role or higher",
            )

    def owns(self, org_id: uuid.UUID | None) -> bool:
        return org_id is not None and org_id == self.org_id


async def _resolve_user(token: str, db: AsyncSession) -> CurrentUser:
    try:
        payload = decode_token(token, expect="access")
    except InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    user = await db.scalar(select(User).where(User.id == payload.user_id))
    if user is None or not user.is_active:
        raise _UNAUTHENTICATED

    # Defence in depth: a token whose org claim no longer matches the stored
    # row (moved user, tampered token, rotated tenant) is rejected outright.
    if user.org_id != payload.org_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token organisation mismatch",
        )

    # Password change / forced logout invalidates outstanding tokens.
    if user.token_version != payload.token_version:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked; please sign in again",
        )

    return CurrentUser(id=user.id, org_id=user.org_id, email=user.email, role=user.role)


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> CurrentUser:
    if credentials is None or not credentials.credentials:
        raise _UNAUTHENTICATED
    return await _resolve_user(credentials.credentials, db)


# --- Role gates -------------------------------------------------------------


def require_role(minimum: UserRole) -> Callable[..., Awaitable[CurrentUser]]:
    """Dependency factory enforcing a minimum role."""

    async def _guard(
        user: Annotated[CurrentUser, Depends(get_current_user)],
    ) -> CurrentUser:
        user.require_role(minimum)
        return user

    return _guard


CurrentUserDep = Annotated[CurrentUser, Depends(get_current_user)]
AnalystDep = Annotated[CurrentUser, Depends(require_role(UserRole.ANALYST))]
AdminDep = Annotated[CurrentUser, Depends(require_role(UserRole.ADMIN))]
DbDep = Annotated[AsyncSession, Depends(get_db)]


# --- WebSocket auth ---------------------------------------------------------


async def authenticate_websocket(token: str | None) -> CurrentUser | None:
    """Resolve a principal for a WebSocket handshake.

    Browsers cannot set headers on ``new WebSocket()``, so the token arrives as
    a query parameter. Returns ``None`` instead of raising so the caller can
    close the socket with a proper code.
    """
    if not token:
        return None
    async with AsyncSessionLocal() as db:
        try:
            return await _resolve_user(token, db)
        except HTTPException:
            return None


# --- Pagination -------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Pagination:
    limit: int
    offset: int


def pagination(
    limit: Annotated[int, Query(ge=1, le=200, description="Max rows to return")] = 50,
    offset: Annotated[int, Query(ge=0, description="Rows to skip")] = 0,
) -> Pagination:
    return Pagination(limit=limit, offset=offset)


PaginationDep = Annotated[Pagination, Depends(pagination)]


__all__ = [
    "AdminDep",
    "AnalystDep",
    "CurrentUser",
    "CurrentUserDep",
    "DbDep",
    "Pagination",
    "PaginationDep",
    "authenticate_websocket",
    "get_current_user",
    "require_role",
]
