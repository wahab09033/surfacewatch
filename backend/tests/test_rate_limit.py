"""Tests for authentication rate limiting.

The properties worth pinning down are not "a 429 appears eventually" but the
ones that are easy to get subtly wrong and impossible to notice in manual
testing:

*   an unknown address is throttled exactly like a real one (no enumeration),
*   a correct password clears the counter (no punishing a fumbled login),
*   the lockout is checked before bcrypt runs (no CPU amplification),
*   a Redis outage lets logins through rather than locking everyone out, and
*   a forged ``X-Forwarded-For`` does not mint a fresh bucket per request.
"""

from __future__ import annotations

import pytest

from config import settings
from core import ratelimit

REGISTER = {
    "org_name": "Limit Co",
    "domain": "limit-test.example",
    "email": "owner@limit-test.example",
    "password": "Limit-P4ssw0rd!",
}

# Counter state is reset between tests by the autouse _clean_redis fixture in
# conftest, which every test in the suite needs for the same reason.


async def _register(client) -> None:
    response = await client.post("/api/auth/register", json=REGISTER)
    assert response.status_code == 201, response.text


async def _login(client, password: str, email: str = REGISTER["email"], **kwargs):
    return await client.post(
        "/api/auth/login", json={"email": email, "password": password}, **kwargs
    )


# --- the basic ceiling ------------------------------------------------------


@pytest.mark.anyio
async def test_repeated_failures_are_eventually_locked_out(client):
    await _register(client)
    limit = settings.rate_limit_login_failures_per_account

    for attempt in range(limit + 1):
        response = await _login(client, "wrong-password")
        assert response.status_code == 401, f"attempt {attempt} -> {response.status_code}"

    # One past the ceiling the answer changes from "wrong" to "stop asking".
    response = await _login(client, "wrong-password")
    assert response.status_code == 429
    assert "Retry-After" in response.headers
    assert int(response.headers["Retry-After"]) > 0


@pytest.mark.anyio
async def test_lockout_survives_a_correct_password(client):
    """Once locked out, the right password does not open the door either.

    Otherwise the 429 leaks nothing but the lockout is pointless: an attacker
    would simply keep going and the one correct guess would still succeed.
    """
    await _register(client)
    for _ in range(settings.rate_limit_login_failures_per_account + 2):
        await _login(client, "wrong-password")

    response = await _login(client, REGISTER["password"])
    assert response.status_code == 429


# --- enumeration resistance -------------------------------------------------


@pytest.mark.anyio
async def test_unknown_address_is_throttled_identically(client):
    """The lockout must not become the enumeration oracle /login avoids.

    A real account and an address that has never existed must produce the same
    status codes in the same order, or "which one got throttled" answers the
    question the vague error message refuses to.
    """
    await _register(client)
    limit = settings.rate_limit_login_failures_per_account

    real, fake = [], []
    for _ in range(limit + 2):
        real.append((await _login(client, "wrong-password")).status_code)
        fake.append(
            (await _login(client, "wrong-password", email="ghost@limit-test.example")).status_code
        )

    assert real == fake
    assert real[-1] == 429  # both ended up locked out


# --- not punishing legitimate users ----------------------------------------


@pytest.mark.anyio
async def test_successful_login_clears_the_failure_counter(client):
    await _register(client)
    limit = settings.rate_limit_login_failures_per_account

    # Fumble a few times, then get it right.
    for _ in range(limit - 1):
        assert (await _login(client, "wrong-password")).status_code == 401
    assert (await _login(client, REGISTER["password"])).status_code == 200

    # The budget is back: another near-full run of failures still is not a lockout.
    for _ in range(limit - 1):
        assert (await _login(client, "wrong-password")).status_code == 401
    assert (await _login(client, REGISTER["password"])).status_code == 200


@pytest.mark.anyio
async def test_failures_against_one_account_do_not_lock_out_another(client):
    """Per-account buckets, or one noisy tenant locks out the whole platform."""
    await _register(client)
    second = {**REGISTER, "email": "other@second-test.example", "domain": "second-test.example",
              "org_name": "Second Co"}
    assert (await client.post("/api/auth/register", json=second)).status_code == 201

    for _ in range(settings.rate_limit_login_failures_per_account + 2):
        await _login(client, "wrong-password")

    # The other account is untouched.
    response = await _login(client, second["password"], email=second["email"])
    assert response.status_code == 200


# --- availability -----------------------------------------------------------


@pytest.mark.anyio
async def test_login_still_works_when_redis_is_down(client, _fake_redis):
    """Fail open. A limiter that fails closed is a cheaper DoS than the one it stops."""
    await _register(client)

    _fake_redis.connected = False
    try:
        response = await _login(client, REGISTER["password"])
    finally:
        _fake_redis.connected = True

    assert response.status_code == 200, response.text


@pytest.mark.anyio
async def test_wrong_password_still_rejected_when_redis_is_down(client, _fake_redis):
    """Failing open applies to throttling only — never to the credential check."""
    await _register(client)

    _fake_redis.connected = False
    try:
        response = await _login(client, "wrong-password")
    finally:
        _fake_redis.connected = True

    assert response.status_code == 401


# --- client identification --------------------------------------------------


def test_forged_forwarded_header_is_ignored_by_default():
    """With no trusted proxies, X-Forwarded-For must not create a new bucket."""
    assert settings.trusted_proxy_count == 0

    def request_with(header: str | None):
        scope_headers = []
        if header is not None:
            scope_headers.append((b"x-forwarded-for", header.encode()))
        from starlette.requests import Request

        return Request(
            {
                "type": "http",
                "headers": scope_headers,
                "client": ("203.0.113.9", 51234),
                "method": "POST",
                "path": "/api/auth/login",
            }
        )

    baseline = ratelimit.client_ip(request_with(None))
    assert baseline == "203.0.113.9"
    # Every forged value must still map to the same bucket as no header at all.
    for forged in ("1.2.3.4", "9.9.9.9, 8.8.8.8", "not-an-ip"):
        assert ratelimit.client_ip(request_with(forged)) == baseline


def test_forwarded_header_is_honoured_when_proxies_are_trusted(monkeypatch):
    """Behind one LB, the client is the last entry the LB appended."""
    from starlette.requests import Request

    monkeypatch.setattr(settings, "trusted_proxy_count", 1)

    def request_with(header: str):
        return Request(
            {
                "type": "http",
                "headers": [(b"x-forwarded-for", header.encode())],
                "client": ("10.0.0.1", 51234),
                "method": "POST",
                "path": "/api/auth/login",
            }
        )

    # Client claimed 1.1.1.1; the LB appended the address it actually saw.
    assert ratelimit.client_ip(request_with("1.1.1.1, 203.0.113.9")) == "203.0.113.9"
    # A single-entry chain is what a direct-to-LB request looks like.
    assert ratelimit.client_ip(request_with("203.0.113.9")) == "203.0.113.9"


# --- other endpoints --------------------------------------------------------


@pytest.mark.anyio
async def test_registration_is_capped_per_ip(client):
    """Unauthenticated and it writes rows — an obvious spam and DoS target."""
    limit = settings.rate_limit_register_per_ip
    statuses = []
    for i in range(limit + 2):
        response = await client.post(
            "/api/auth/register",
            json={
                "org_name": f"Spam {i}",
                "domain": f"spam{i}.example",
                "email": f"spam{i}@spam{i}.example",
                "password": "Spam-P4ssw0rd!",
            },
        )
        statuses.append(response.status_code)

    assert 429 in statuses
    assert statuses.index(429) == limit


@pytest.mark.anyio
async def test_password_change_is_throttled(client):
    """A stolen access token must not be usable to brute-force the old password."""
    await _register(client)
    token = (await _login(client, REGISTER["password"])).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    limit = settings.rate_limit_login_failures_per_account

    statuses = []
    for _ in range(limit + 2):
        response = await client.post(
            "/api/auth/password",
            json={"current_password": "not-the-password", "new_password": "Brand-N3w-Pass!"},
            headers=headers,
        )
        statuses.append(response.status_code)

    assert statuses[0] == 400
    assert 429 in statuses
