"""Refresh-token rotation: single-use tokens with family-wide reuse detection.

The contract under test:

* every refresh token is revoked when it is spent, and its replacement is
  issued in the same transaction;
* a spent token presented again is treated as theft and revokes the whole
  family — the replacement is useless to the replaying party too;
* two concurrent refreshes of the same token cannot both succeed;
* logout revokes the presented session; password changes and deactivation
  revoke every session for the user;
* a token is bound to its user and organisation, and a mismatch kills the
  family rather than being ignored.
"""

from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest
from sqlalchemy import delete, select

from db.database import session_scope
from models import RefreshSession, User
from models.base import utcnow
from models.refresh_session import hash_refresh_token
from schemas.auth import TokenPair

pytestmark = pytest.mark.asyncio

REFRESH = "/api/auth/refresh"
LOGOUT = "/api/auth/logout"
PASSWORD = "correct-horse-battery-staple-7"


# --- helpers ----------------------------------------------------------------


async def _register(client, slug: str = "rot", domain: str | None = None) -> dict:
    body = {
        "org_name": f"{slug} corp",
        "domain": domain or f"{slug}-corp.example",
        "email": f"owner@{slug}-corp.example",
        "password": PASSWORD,
        "full_name": f"{slug} owner",
    }
    resp = await client.post("/api/auth/register", json=body)
    assert resp.status_code == 201, resp.text
    return resp.json()


async def _refresh(client, token: str) -> tuple[int, dict]:
    resp = await client.post(REFRESH, json={"refresh_token": token})
    return resp.status_code, resp.json()


def _session_row(token: str) -> RefreshSession | None:
    """The DB row behind ``token``, or None."""
    with session_scope() as session:
        return session.scalar(
            select(RefreshSession).where(RefreshSession.token_hash == hash_refresh_token(token))
        )


def _family_rows(token: str) -> list[RefreshSession]:
    with session_scope() as session:
        row = session.scalar(
            select(RefreshSession).where(RefreshSession.token_hash == hash_refresh_token(token))
        )
        if row is None:
            return []
        return list(
            session.scalars(
                select(RefreshSession).where(RefreshSession.family_id == row.family_id)
            )
        )


# --- rotation ---------------------------------------------------------------


async def test_normal_refresh_rotates_and_returns_a_working_pair(client):
    tokens = await _register(client)
    old = tokens["refresh_token"]

    status, body = await _refresh(client, old)
    assert status == 200, body
    new = TokenPair(**body)

    assert new.refresh_token != old
    assert new.access_token

    # The old token is spent: the row is revoked and points at its successor.
    old_row = _session_row(old)
    assert old_row.revoked_at is not None
    new_row = _session_row(new.refresh_token)
    assert new_row is not None and new_row.revoked_at is None
    assert new_row.family_id == old_row.family_id
    assert old_row.replaced_by == new_row.id

    # And the new pair genuinely works for authenticated calls.
    me = await client.get(
        "/api/auth/me", headers={"Authorization": f"Bearer {new.access_token}"}
    )
    assert me.status_code == 200, me.text


async def test_spent_token_is_rejected_and_revokes_the_family(client):
    tokens = await _register(client)
    status, body = await _refresh(client, tokens["refresh_token"])
    assert status == 200
    new_token = body["refresh_token"]

    # The legitimate holder has rotated once. Replaying the OLD token is the
    # attacker signature: the family must die, taking the new token with it.
    status, body = await _refresh(client, tokens["refresh_token"])
    assert status == 401, body
    assert "reuse" in body["detail"].lower()

    for row in _family_rows(new_token):
        assert row.revoked_at is not None, f"family member {row.id} still active"

    # The replacement is dead too, and replaying IT is also reuse.
    status, body = await _refresh(client, new_token)
    assert status == 401
    assert "reuse" in body["detail"].lower()


async def test_concurrent_refresh_cannot_rotate_the_same_token_twice(client):
    tokens = await _register(client)
    old = tokens["refresh_token"]

    # Fire two refreshes of the same token at once. FOR UPDATE serialises them:
    # one wins the rotation, the loser sees a revoked row and revokes the family.
    results = await asyncio.gather(
        _refresh(client, old), _refresh(client, old), return_exceptions=True
    )
    statuses = sorted(r[0] for r in results if isinstance(r, tuple))
    assert statuses == [200, 401], statuses

    winner_body = next(r[1] for r in results if r[0] == 200)
    loser_detail = next(r[1] for r in results if r[0] == 401)
    assert "reuse" in loser_detail["detail"].lower()

    # Reuse detection killed the family, so even the winner's token is dead.
    for row in _family_rows(winner_body["refresh_token"]):
        assert row.revoked_at is not None


async def test_expired_token_is_rejected(client):
    tokens = await _register(client)
    old = tokens["refresh_token"]

    with session_scope() as session:
        row = session.scalar(
            select(RefreshSession).where(
                RefreshSession.token_hash == hash_refresh_token(old)
            )
        )
        row.expires_at = utcnow() - timedelta(seconds=1)
        session.commit()

    status, body = await _refresh(client, old)
    assert status == 401
    assert "expired" in body["detail"].lower()

    # Expiry is terminal: the token cannot be revived by waiting.
    assert _session_row(old).revoked_at is not None


# --- revocation -------------------------------------------------------------


async def test_logout_revokes_the_presented_session(client):
    tokens = await _register(client)
    old = tokens["refresh_token"]

    resp = await client.post(LOGOUT, json={"refresh_token": old})
    assert resp.status_code == 200, resp.text

    assert _session_row(old).revoked_at is not None
    status, _ = await _refresh(client, old)
    assert status == 401


async def test_logout_is_idempotent_and_does_not_confirm_validity(client):
    tokens = await _register(client)
    # Unknown garbage token: still 200, no validity oracle.
    resp = await client.post(LOGOUT, json={"refresh_token": "not-a-real-token"})
    assert resp.status_code == 200, resp.text
    assert _session_row("not-a-real-token") is None

    # Logging out twice is fine.
    resp = await client.post(LOGOUT, json={"refresh_token": tokens["refresh_token"]})
    assert resp.status_code == 200
    resp = await client.post(LOGOUT, json={"refresh_token": tokens["refresh_token"]})
    assert resp.status_code == 200


async def test_password_change_revokes_every_session(client):
    tokens = await _register(client)
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    resp = await client.post(
        "/api/auth/password",
        json={"current_password": PASSWORD, "new_password": "correct-horse-battery-staple-8"},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text

    # The pre-change refresh token is dead; replaying it is treated as reuse.
    status, body = await _refresh(client, tokens["refresh_token"])
    assert status == 401
    assert "revoked" in body["detail"].lower()
    assert _session_row(tokens["refresh_token"]).revoked_at is not None


async def test_deactivation_revokes_the_users_sessions(client):
    tokens_a = await _register(client, "deact")
    headers = {"Authorization": f"Bearer {tokens_a['access_token']}"}
    me = (await client.get("/api/auth/me", headers=headers)).json()

    resp = await client.delete(f"/api/auth/users/{me['id']}", headers=headers)
    assert resp.status_code == 400, resp.text  # cannot deactivate yourself

    # The owner mints a second owner, who then deactivates the first.
    invite = await client.post(
        "/api/auth/users",
        json={"email": "admin2@deact-corp.example", "password": PASSWORD, "role": "owner"},
        headers=headers,
    )
    assert invite.status_code == 201, invite.text
    login = await client.post(
        "/api/auth/login",
        json={"email": "admin2@deact-corp.example", "password": PASSWORD},
    )
    admin2_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    resp = await client.delete(f"/api/auth/users/{me['id']}", headers=admin2_headers)
    assert resp.status_code == 200, resp.text

    status, _ = await _refresh(client, tokens_a["refresh_token"])
    assert status == 401
    assert _session_row(tokens_a["refresh_token"]).revoked_at is not None


# --- cross-tenant and cross-user binding ------------------------------------


async def test_deactivated_users_token_is_rejected_and_kills_its_family(client):
    tokens_a = await _register(client, "crossa")

    # Rotate once so there is a family to kill.
    status, body = await _refresh(client, tokens_a["refresh_token"])
    assert status == 200
    new_token = body["refresh_token"]

    # The account is deactivated; the replacement token dies with the family.
    with session_scope() as session:
        user = session.scalar(
            select(User).where(User.email == "owner@crossa-corp.example")
        )
        user.is_active = False
        session.commit()

    status, _ = await _refresh(client, new_token)
    assert status == 401
    for row in _family_rows(new_token):
        assert row.revoked_at is not None


async def test_cross_organisation_token_is_rejected(client):
    tokens_a = await _register(client, "orgx")
    await _register(client, "orgy")

    # Move A's user into B's organisation: the token's org claim no longer
    # matches the stored row, so the token is rejected and the family revoked.
    with session_scope() as session:
        user = session.scalar(
            select(User).where(User.email == "owner@orgx-corp.example")
        )
        b_org = session.scalar(
            select(User).where(User.email == "owner@orgy-corp.example")
        )
        user.org_id = b_org.org_id
        session.commit()

    status, _ = await _refresh(client, tokens_a["refresh_token"])
    assert status == 401
    assert _session_row(tokens_a["refresh_token"]).revoked_at is not None


async def test_access_token_cannot_be_spent_at_the_refresh_endpoint(client):
    tokens = await _register(client)
    status, body = await _refresh(client, tokens["access_token"])
    assert status == 401
    assert "refresh" in body["detail"].lower()


async def test_refresh_requires_a_real_session_row(client):
    """A signature-valid token with no DB row is rejected.

    This is what happens to every token issued before rotation existed, and to
    any token whose row was purged — neither should keep working outside the
    control that replaced them.
    """
    tokens = await _register(client)

    # Delete the row behind a freshly issued token: signature still valid.
    with session_scope() as session:
        session.execute(
            delete(RefreshSession).where(
                RefreshSession.token_hash == hash_refresh_token(tokens["refresh_token"])
            )
        )
        session.commit()

    status, body = await _refresh(client, tokens["refresh_token"])
    assert status == 401
    assert "invalid" in body["detail"].lower()


async def test_raw_refresh_tokens_are_never_stored(client):
    tokens = await _register(client)
    row = _session_row(tokens["refresh_token"])

    with session_scope() as session:
        stored = session.scalar(
            select(RefreshSession).where(RefreshSession.id == row.id)
        )
        assert tokens["refresh_token"] not in stored.token_hash
        assert stored.token_hash == hash_refresh_token(tokens["refresh_token"])
        assert len(stored.token_hash) == 64  # sha256 hex
