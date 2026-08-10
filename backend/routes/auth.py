"""Authentication and user management.

Registration creates an organisation plus its owner. Everything else in the
API requires a valid access token, and every query is filtered by the
``org_id`` carried in that token.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from starlette.concurrency import run_in_threadpool

from config import settings
from core.deps import AdminDep, CurrentUserDep, DbDep
from core.passwords import assert_not_breached
from core.ratelimit import (
    LOGIN_ACCOUNT,
    LOGIN_IP,
    PASSWORD_USER,
    REFRESH_IP,
    REGISTER_IP,
    RateLimit,
    account_identity,
    assert_under,
    clear_failures,
    record_failure,
)
from core.security import (
    InvalidTokenError,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from models import Organisation, User, UserRole
from schemas.auth import (
    LoginRequest,
    OrganisationOut,
    PasswordChange,
    RefreshRequest,
    RegisterRequest,
    SlackWebhookUpdate,
    TokenPair,
    UserInvite,
    UserOut,
)
from schemas.common import Message

router = APIRouter(prefix="/api/auth", tags=["auth"])

_INVALID_CREDENTIALS = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Incorrect email or password",
    headers={"WWW-Authenticate": "Bearer"},
)


def _issue_tokens(user: User) -> TokenPair:
    kwargs = {
        "user_id": user.id,
        "org_id": user.org_id,
        "role": user.role.value,
        "token_version": user.token_version,
    }
    return TokenPair(
        access_token=create_access_token(**kwargs),
        refresh_token=create_refresh_token(**kwargs),
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.post(
    "/register",
    response_model=TokenPair,
    status_code=status.HTTP_201_CREATED,
    summary="Create an organisation and its owner account",
    dependencies=[Depends(RateLimit(REGISTER_IP))],
)
async def register(body: RegisterRequest, db: DbDep) -> TokenPair:
    # After the schema's offline checks, before any row is written. Network I/O,
    # so it cannot live in the validator — see core.passwords.assert_not_breached.
    await assert_not_breached(body.password)

    existing = await db.scalar(
        select(User).where(func.lower(User.email) == body.email.lower())
    )
    if existing is not None:
        # Deliberately vague: this endpoint is unauthenticated, and a precise
        # error would turn it into an account-enumeration oracle.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Unable to register with those details",
        )

    org = Organisation(
        name=body.org_name.strip(),
        domain=body.domain,
        verified_domains=[body.domain],
    )
    db.add(org)
    await db.flush()

    user = User(
        org_id=org.id,
        email=body.email.lower(),
        full_name=body.full_name,
        role=UserRole.OWNER,
        password_hash=hash_password(body.password),
    )
    db.add(user)

    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Unable to register with those details",
        ) from exc

    await db.refresh(user)
    return _issue_tokens(user)


@router.post(
    "/login",
    response_model=TokenPair,
    summary="Exchange credentials for tokens",
    dependencies=[Depends(RateLimit(LOGIN_IP))],
)
async def login(body: LoginRequest, db: DbDep) -> TokenPair:
    # Checked before the bcrypt comparison below, not after. A locked-out
    # caller must not be able to keep spending a 12-round hash per request —
    # that turns the login endpoint into a CPU amplifier pointed at ourselves.
    identity = account_identity(body.email)
    await assert_under(LOGIN_ACCOUNT, identity)

    user = await db.scalar(select(User).where(func.lower(User.email) == body.email.lower()))

    # Always run a hash comparison, even for an unknown address, so response
    # timing does not reveal whether the account exists.
    password_ok = verify_password(
        body.password,
        user.password_hash if user else "$2b$12$" + "." * 53,
    )
    if user is None or not password_ok:
        # Charged against the submitted address whether or not it exists —
        # counting only real accounts would make the lockout an enumeration
        # oracle, undoing the care taken over the message and the timing.
        await record_failure(LOGIN_ACCOUNT, identity)
        raise _INVALID_CREDENTIALS
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="This account has been disabled"
        )

    # A correct password clears the counter: someone who mistypes twice and then
    # gets it right should not carry those failures for the rest of the window.
    await clear_failures(LOGIN_ACCOUNT, identity)

    user.last_login_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(user)
    return _issue_tokens(user)


@router.post(
    "/refresh",
    response_model=TokenPair,
    summary="Rotate an expiring access token",
    dependencies=[Depends(RateLimit(REFRESH_IP))],
)
async def refresh(body: RefreshRequest, db: DbDep) -> TokenPair:
    try:
        payload = decode_token(body.refresh_token, expect="refresh")
    except InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid refresh token: {exc}"
        ) from exc

    user = await db.scalar(select(User).where(User.id == payload.user_id))
    if user is None or not user.is_active or user.org_id != payload.org_id:
        raise _INVALID_CREDENTIALS
    if user.token_version != payload.token_version:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token has been revoked"
        )
    return _issue_tokens(user)


@router.get("/me", response_model=UserOut, summary="Current user")
async def me(current: CurrentUserDep, db: DbDep) -> User:
    user = await db.scalar(
        select(User).where(User.id == current.id, User.org_id == current.org_id)
    )
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


@router.get("/organisation", response_model=OrganisationOut, summary="Current organisation")
async def my_organisation(current: CurrentUserDep, db: DbDep) -> OrganisationOut:
    org = await db.scalar(select(Organisation).where(Organisation.id == current.org_id))
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organisation not found")
    # from_org rather than returning the model: it drops the Slack webhook URL
    # and substitutes a redacted hint. Returning `org` directly would serialise
    # whatever fields the schema declares, and the credential must not be one.
    return OrganisationOut.from_org(org)


@router.put(
    "/organisation/slack-webhook",
    response_model=OrganisationOut,
    summary="Set or clear the Slack alert webhook",
)
async def set_slack_webhook(
    body: SlackWebhookUpdate, current: AdminDep, db: DbDep
) -> OrganisationOut:
    """Configure where critical-finding alerts are posted.

    Admin+ because the URL is a credential for a channel the whole team reads,
    and because a viewer being able to redirect security alerts to a channel
    they control is a plausible way to hide an intrusion.

    The URL is validated to be an https hooks.slack.com incoming webhook — see
    workers/notifier.validate_webhook_url for why that restriction is a
    security control and not just tidiness.
    """
    org = await db.scalar(select(Organisation).where(Organisation.id == current.org_id))
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organisation not found")

    org.slack_webhook_url = body.webhook_url
    await db.commit()
    await db.refresh(org)
    return OrganisationOut.from_org(org)


@router.post(
    "/organisation/slack-webhook/test",
    response_model=Message,
    summary="Send a test message to the configured Slack webhook",
)
async def test_slack_webhook(current: AdminDep, db: DbDep) -> Message:
    """Post a harmless test message.

    Worth its own endpoint: a webhook that was revoked in Slack still looks
    configured here, and the alternative way to discover that is missing a real
    critical alert. Runs inline rather than through Celery because the caller
    is waiting on the answer — that is the entire point of a test button.
    """
    org = await db.scalar(select(Organisation).where(Organisation.id == current.org_id))
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organisation not found")
    if not org.slack_webhook_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No Slack webhook is configured for this organisation",
        )

    from workers.notifier import post as slack_post

    payload = {
        "text": f"SurfaceWatch test alert — {org.name}",
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*SurfaceWatch is connected.*\n"
                        f"Critical findings for *{org.name}* will be posted here. "
                        f"This is a test message — no action is needed."
                    ),
                },
            }
        ],
    }

    # httpx is sync inside notifier.post, so it goes to a thread rather than
    # blocking the event loop for the duration of the round trip.
    delivered = await run_in_threadpool(slack_post, org.slack_webhook_url, payload)
    if not delivered:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=(
                "Slack rejected the message. The webhook may have been revoked — "
                "generate a new one in Slack and save it again."
            ),
        )
    return Message(detail="Test message delivered to Slack.")


@router.post("/password", response_model=Message, summary="Change your password")
async def change_password(body: PasswordChange, current: CurrentUserDep, db: DbDep) -> Message:
    # Authenticated, but still throttled: it verifies the *current* password, so
    # a stolen access token would otherwise let someone brute-force the original
    # credential — worth far more than the session they already hold, because
    # people reuse it elsewhere.
    identity = account_identity(str(current.id))
    await assert_under(PASSWORD_USER, identity)

    user = await db.scalar(
        select(User).where(User.id == current.id, User.org_id == current.org_id)
    )
    if user is None or not verify_password(body.current_password, user.password_hash):
        await record_failure(PASSWORD_USER, identity)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect"
        )

    # Only after the current password checked out, so this endpoint cannot be
    # used as a free breach-corpus oracle by someone without the credential.
    await assert_not_breached(body.new_password)

    await clear_failures(PASSWORD_USER, identity)
    user.password_hash = hash_password(body.new_password)
    # Invalidate every token issued before this change.
    user.token_version += 1
    await db.commit()
    return Message(detail="Password updated. Existing sessions have been signed out.")


# --- Team management (admin+) ----------------------------------------------


@router.get("/users", response_model=list[UserOut], summary="List users in your organisation")
async def list_users(current: CurrentUserDep, db: DbDep) -> list[User]:
    result = await db.scalars(
        select(User).where(User.org_id == current.org_id).order_by(User.created_at)
    )
    return list(result)


@router.post(
    "/users",
    response_model=UserOut,
    status_code=status.HTTP_201_CREATED,
    summary="Add a user to your organisation",
)
async def invite_user(body: UserInvite, current: AdminDep, db: DbDep) -> User:
    await assert_not_breached(body.password)

    # Only an owner may mint another owner.
    if body.role == UserRole.OWNER and current.role != UserRole.OWNER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only an owner can grant the owner role",
        )

    user = User(
        org_id=current.org_id,
        email=body.email.lower(),
        full_name=body.full_name,
        role=body.role,
        password_hash=hash_password(body.password),
    )
    db.add(user)
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with that email already exists in this organisation",
        ) from exc

    await db.refresh(user)
    return user


@router.delete(
    "/users/{user_id}", response_model=Message, summary="Deactivate a user"
)
async def deactivate_user(user_id: uuid.UUID, current: AdminDep, db: DbDep) -> Message:
    if user_id == current.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="You cannot deactivate yourself"
        )

    # Scoped by org_id: an admin cannot touch a user in another tenant, and the
    # 404 does not confirm whether that id exists elsewhere.
    user = await db.scalar(
        select(User).where(User.id == user_id, User.org_id == current.org_id)
    )
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if user.role == UserRole.OWNER and current.role != UserRole.OWNER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Only an owner can remove an owner"
        )

    user.is_active = False
    user.token_version += 1  # kill their live sessions
    await db.commit()
    return Message(detail=f"{user.email} has been deactivated")
