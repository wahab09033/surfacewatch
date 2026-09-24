"""Authentication and user management.

Registration creates an organisation plus its owner. Everything else in the
API requires a valid access token, and every query is filtered by the
``org_id`` carried in that token.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

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
from models import (
    DomainVerification,
    Organisation,
    RefreshSession,
    User,
    UserRole,
)
from models.refresh_session import hash_refresh_token
from schemas.auth import (
    LoginRequest,
    LogoutRequest,
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

_REFRESH_INVALID = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token"
)


async def _issue_tokens(user: User, db: DbDep) -> TokenPair:
    """Mint an access/refresh pair and persist the refresh session.

    Every refresh token gets a server-side row recording its hash and family.
    The row is what makes rotation and reuse detection possible — see
    models.refresh_session for the threat model.
    """
    kwargs = {
        "user_id": user.id,
        "org_id": user.org_id,
        "role": user.role.value,
        "token_version": user.token_version,
    }
    refresh_token = create_refresh_token(**kwargs)
    db.add(
        RefreshSession(
            user_id=user.id,
            org_id=user.org_id,
            token_hash=hash_refresh_token(refresh_token),
            expires_at=datetime.now(timezone.utc)
            + timedelta(days=settings.refresh_token_expire_days),
        )
    )
    await db.commit()
    return TokenPair(
        access_token=create_access_token(**kwargs),
        refresh_token=refresh_token,
        expires_in=settings.access_token_expire_minutes * 60,
    )


async def _revoke_family(db: DbDep, session: RefreshSession) -> None:
    """Revoke every active session sharing ``session``'s family.

    Called when a token is replayed after rotation. By then the legitimate
    holder has usually rotated once already, so the replay is almost always a
    thief — and killing the whole family is what stops them using the token
    they stole.
    """
    now = datetime.now(timezone.utc)
    rows = await db.scalars(
        select(RefreshSession).where(
            RefreshSession.family_id == session.family_id,
            RefreshSession.revoked_at.is_(None),
        )
    )
    for row in rows:
        row.revoked_at = now


async def _revoke_user_sessions(db: DbDep, user_id: uuid.UUID) -> None:
    """Revoke every refresh session for one user (password change, deactivation)."""
    now = datetime.now(timezone.utc)
    rows = await db.scalars(
        select(RefreshSession).where(
            RefreshSession.user_id == user_id,
            RefreshSession.revoked_at.is_(None),
        )
    )
    for row in rows:
        row.revoked_at = now


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
        # Deliberately empty, where this used to be ``[body.domain]``.
        # ``verified_domains`` is scanning authorisation, and registration is open
        # to the public: seeding it from the signup form meant anyone could claim
        # microsoft.com and legitimately port-scan it from this deployment. The
        # PENDING claim created below is the path in, via a DNS record only the
        # real owner can publish.
        verified_domains=[],
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
    # Flushed before the claim below, because ``created_by`` needs ``user.id`` and
    # the primary-key default is applied Python-side at flush, not at construction.
    await db.flush()

    # Same transaction as the org and the owner, so a new account lands in the app
    # with its challenge already waiting instead of having to re-enter the domain
    # it just typed. Until this claim verifies the account can scan nothing —
    # which is the intended posture, and what the empty state in the UI explains.
    db.add(
        DomainVerification(
            org_id=org.id,
            created_by=user.id,
            domain=body.domain,
        )
    )

    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Unable to register with those details",
        ) from exc

    await db.refresh(user)
    return await _issue_tokens(user, db)


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
    return await _issue_tokens(user, db)


@router.post(
    "/refresh",
    response_model=TokenPair,
    summary="Rotate an expiring access token",
    dependencies=[Depends(RateLimit(REFRESH_IP))],
)
async def refresh(body: RefreshRequest, db: DbDep) -> TokenPair:
    """Exchange a refresh token for a fresh pair, rotating the refresh token.

    Rotation is single-use with reuse detection: the presented token is revoked
    in the same transaction that issues its replacement, so a token presented
    twice can only mean one of the two uses was the thief. Reuse revokes the
    whole session family. See models.refresh_session for the threat model.
    """
    try:
        payload = decode_token(body.refresh_token, expect="refresh")
    except InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid refresh token: {exc}"
        ) from exc

    # FOR UPDATE serialises concurrent refreshes of the same token: the second
    # request blocks until the first commits, then sees revoked_at set and is
    # treated as the reuse it is.
    session = await db.scalar(
        select(RefreshSession)
        .where(RefreshSession.token_hash == hash_refresh_token(body.refresh_token))
        .with_for_update()
    )

    user = await db.scalar(select(User).where(User.id == payload.user_id))
    if user is None or not user.is_active or user.org_id != payload.org_id:
        if session is not None:
            # An account that vanished or moved org while its token is being
            # spent is a session that must not survive either.
            await _revoke_family(db, session)
            await db.commit()
        raise _INVALID_CREDENTIALS
    if user.token_version != payload.token_version:
        if session is not None:
            await _revoke_family(db, session)
            await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been revoked; please sign in again",
        )

    # Signed by us (signature + user checks passed) but with no row. Possible
    # when the row predates rotation, was purged by a database reset, or the
    # token is a forgery that reused a stolen signature — none of which should
    # be honoured silently.
    if session is None:
        raise _REFRESH_INVALID

    now = datetime.now(timezone.utc)
    if session.revoked_at is not None:
        # A rotated token presented again. The legitimate holder already moved
        # on to the replacement, so whoever is presenting this is the thief —
        # kill the whole family so the replacement is useless to them too.
        await _revoke_family(db, session)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token reuse detected — this session has been revoked",
        )

    if session.expires_at <= now:
        session.revoked_at = now
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token has expired"
        )

    session.last_used_at = now

    kwargs = {
        "user_id": user.id,
        "org_id": user.org_id,
        "role": user.role.value,
        "token_version": user.token_version,
    }
    new_refresh = create_refresh_token(**kwargs)
    replacement = RefreshSession(
        id=uuid.uuid4(),
        user_id=user.id,
        org_id=user.org_id,
        token_hash=hash_refresh_token(new_refresh),
        family_id=session.family_id,
        expires_at=now + timedelta(days=settings.refresh_token_expire_days),
    )
    db.add(replacement)
    # Flush before revoking the old row: ``session.replaced_by`` is a
    # self-referential FK, and the UPDATE would violate it if the successor row
    # did not exist yet.
    await db.flush()
    session.revoked_at = now
    session.replaced_by = replacement.id
    await db.commit()

    return TokenPair(
        access_token=create_access_token(**kwargs),
        refresh_token=new_refresh,
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.post("/logout", response_model=Message, summary="Sign out this device")
async def logout(body: LogoutRequest, db: DbDep) -> Message:
    """Revoke the presented refresh session.

    Always succeeds: the client clears its stored tokens either way, and a
    logout endpoint confirming whether a token was ever valid is information
    nobody needs. The family's other sessions (other devices) are untouched —
    this is "sign out this browser", not "sign out everywhere". Password
    changes and account deactivation revoke every session.
    """
    session = await db.scalar(
        select(RefreshSession).where(
            RefreshSession.token_hash == hash_refresh_token(body.refresh_token)
        )
    )
    if session is not None and session.revoked_at is None:
        session.revoked_at = datetime.now(timezone.utc)
        await db.commit()
    return Message(detail="Signed out.")


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
    # Invalidate every token issued before this change: the JWT token_version
    # covers outstanding access/refresh JWTs, and the refresh-session rows must
    # be revoked too so a replayed pre-change refresh token is treated as the
    # reuse it is rather than being honoured.
    user.token_version += 1
    await _revoke_user_sessions(db, user.id)
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
    await _revoke_user_sessions(db, user.id)
    await db.commit()
    return Message(detail=f"{user.email} has been deactivated")
