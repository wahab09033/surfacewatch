"""Tests for password strength checking.

Two failure modes matter and they pull in opposite directions. Too permissive
and the policy accepts ``password1234`` — which the previous
length-plus-character-class rule did, while its docstring claimed to reject
breach-corpus passwords. Too strict and it rejects passwords that are actually
strong, which pushes people toward writing them down.

So every test here is paired: whatever a rule rejects, something structurally
similar and genuinely strong must still get through.
"""

from __future__ import annotations

import pytest

from core import passwords

# --- the case that motivated this -------------------------------------------


def test_the_password_that_used_to_be_accepted_is_rejected():
    """12 chars, a letter and a digit — and near the top of every breach list.

    This exact string passed the old policy. It is the regression test for the
    whole module.
    """
    assert passwords.check("password1234") is not None


@pytest.mark.parametrize(
    "password",
    [
        "password1234",
        "Password2024!",
        "P@ssw0rd123!",
        "letmein12345",
        "welcome12345",
        "admin1234567",
        "iloveyou1234",
        "changeme1234",
        "sunshine1234",
        "football1234",
        "Monkey123456",
        "dragon123456",
        "Adm1n1strator",
    ],
)
def test_common_passwords_are_rejected(password):
    assert passwords.check(password) is not None, password


@pytest.mark.parametrize(
    "password",
    [
        "qwertyuiop12",  # keyboard row
        "1234567890ab",  # digit run
        "abcabcabcabc",  # repeated unit
        "aaaaaaaaaaaa",  # one character
        "abcdefghijkl",  # alphabet
        "zxcvbnmasdfgh",  # two rows, back to back
        "poiuytrewqlkjhgfdsa",  # rows walked backwards
    ],
)
def test_structural_patterns_are_rejected(password):
    assert passwords.check(password) is not None, password


def test_a_long_password_made_only_of_keyboard_runs_is_rejected():
    """The whole keyboard twice: 70 characters, and it used to be accepted.

    The first version of this check asked whether a *single* run covered most
    of the password. No keyboard row is longer than 26 characters, so past
    ~37 characters no run could ever clear the bar and every length check
    above it passed. Coverage is measured across all runs now, because several
    runs back to back are exactly as guessable as one.
    """
    keyboard = "qwertyuiopasdfghjklzxcvbnm1234567890"
    password = (keyboard * 2)[:70]
    assert len(password) == 70
    assert passwords.check(password) is not None


def test_run_detection_does_not_condemn_ordinary_passphrases():
    """The paired half: a four-character floor is short enough to worry about.

    ``_KEYBOARD_ROWS`` includes the full alphabet, so a short alphabetical
    stretch inside a real word ("burst", "defer") must not read as a keyboard
    walk. What matters is the fraction of the password those runs account for.
    """
    for password in (
        "burst-defer-hijack-42",
        "vault-12345-harbour",
        "Ghjk-Wander-Moss-3",
    ):
        assert passwords.check(password) is None, password


# --- and the other direction ------------------------------------------------


@pytest.mark.parametrize(
    "password",
    [
        "correct-horse-battery-staple-7",
        "glacier-tumbling-vault-19",
        "Tr0ub4dor&3xkcd-ref",
        "Xk9$mQ2vLp7wRt",
        "purple-monolith-8842",
        "Quiet-Harbour-Lantern-9",
        "kY7#nBv2$xQ9wL",
        "tangerine-drift-90210",
        # Contains a mutated common word but is not built from one. Rejecting
        # this tier is how a strength policy makes people write passwords down.
        "Brand-N3w-Pass!",
        "my-admin-console-key-7",
        "the-monkey-and-the-dragon-4",
    ],
)
def test_strong_passwords_are_accepted(password):
    assert passwords.check(password) is None, password


# --- account context --------------------------------------------------------


def test_password_derived_from_the_account_is_rejected():
    """Guessable by anyone who can see the login form."""
    context = ("acme", "acmecorp", "owner")
    assert passwords.check("acme-corp-2024x", context=context) is not None
    assert passwords.check("acmecorp12345", context=context) is not None


def test_context_does_not_reject_an_unrelated_password():
    assert passwords.check("glacier-tumbling-vault-19", context=("acme", "acmecorp")) is None


def test_context_tolerates_a_coincidental_shared_word():
    """A shared word is not the same as a password built from the org name.

    "my-glacier-vault-42" for an org called Vault Corp is strong; rejecting it
    is the kind of false positive that makes people append "1" to something
    weaker until the form stops complaining.
    """
    assert passwords.check("my-glacier-vault-42", context=("vault", "vaultcorp")) is None
    assert passwords.check("Limit-P4ssw0rd!", context=("limit", "limitco")) is None


# --- boundaries -------------------------------------------------------------


def test_length_floor():
    assert passwords.check("Xk9$mQ2vLp") is not None  # 10 chars
    assert passwords.check("Xk9$mQ2vLp7w") is None  # 12


def test_bcrypt_byte_ceiling_is_enforced():
    """Past 72 bytes bcrypt silently truncates.

    Accepting a longer password would mean the strength the user chose is not
    the strength stored, and two different passwords could open the account.
    """
    assert passwords.check("Xk9$mQ2vLp7w" + "a" * 100) is not None
    # Multi-byte characters count as bytes, not characters.
    assert passwords.check("Pässwörtchen-Ünïcode-" + "é" * 30) is not None


def test_surrounding_whitespace_is_rejected():
    """It survives storage but never survives a copy-paste."""
    assert passwords.check(" glacier-tumbling-vault-19") is not None
    assert passwords.check("glacier-tumbling-vault-19 ") is not None


# --- HIBP layer -------------------------------------------------------------


def test_pwned_lookup_sends_only_a_hash_prefix(monkeypatch):
    """k-anonymity: five hex characters leave the process, nothing more."""
    import hashlib

    captured = {}

    class _Response:
        text = "0000000000000000000000000000000000A:3\nFFFF:9"

        def raise_for_status(self):
            return None

    def fake_get(url, **kwargs):
        captured["url"] = url
        return _Response()

    import httpx

    monkeypatch.setattr(httpx, "get", fake_get)
    password = "glacier-tumbling-vault-19"
    passwords.pwned_count(password)

    digest = hashlib.sha1(password.encode()).hexdigest().upper()  # noqa: S324
    assert captured["url"].endswith(digest[:5])
    # The rest of the hash, and the password, must not appear anywhere in it.
    assert digest[5:] not in captured["url"]
    assert password not in captured["url"]


def test_pwned_count_reports_a_match(monkeypatch):
    import hashlib

    password = "password1234"
    suffix = hashlib.sha1(password.encode()).hexdigest().upper()[5:]  # noqa: S324

    class _Response:
        text = f"AAAA:1\n{suffix}:24230577\nBBBB:2"

        def raise_for_status(self):
            return None

    import httpx

    monkeypatch.setattr(httpx, "get", lambda url, **kw: _Response())
    assert passwords.pwned_count(password) == 24230577


def test_pwned_lookup_fails_open(monkeypatch):
    """A slow third party must not break registration.

    The offline checks have already run either way, so failing open here costs
    much less than an auth form that goes down when an external API does.
    """
    import httpx

    def boom(url, **kwargs):
        raise httpx.ConnectTimeout("no network")

    monkeypatch.setattr(httpx, "get", boom)
    assert passwords.pwned_count("anything-at-all-42") == 0


# --- the HIBP layer as wired into the routes --------------------------------


def test_hibp_check_is_off_by_default():
    """It makes registration depend on a third party, so it is opt-in."""
    from config import settings

    assert settings.password_hibp_check_enabled is False


@pytest.mark.anyio
async def test_registration_makes_no_network_call_when_disabled(client, monkeypatch):
    """Off means off — no outbound request at all, not a call that is ignored."""
    import httpx

    def forbidden(url, **kwargs):
        raise AssertionError(f"unexpected outbound request to {url}")

    monkeypatch.setattr(httpx, "get", forbidden)
    response = await client.post(
        "/api/auth/register",
        json={
            "org_name": "Nonet Co",
            "domain": "nonet.example",
            "email": "owner@nonet.example",
            "password": "glacier-tumbling-vault-19",
        },
    )
    assert response.status_code == 201, response.text


@pytest.mark.anyio
async def test_registration_refuses_a_breached_password_when_enabled(client, monkeypatch):
    from config import settings

    monkeypatch.setattr(settings, "password_hibp_check_enabled", True)
    monkeypatch.setattr(passwords, "pwned_count", lambda p, **kw: 4_213)

    response = await client.post(
        "/api/auth/register",
        json={
            "org_name": "Breach Co",
            "domain": "breach.example",
            "email": "owner@breach.example",
            "password": "glacier-tumbling-vault-19",
        },
    )
    assert response.status_code == 400
    assert "data breach" in response.json()["detail"]


@pytest.mark.anyio
async def test_registration_allows_a_clean_password_when_enabled(client, monkeypatch):
    from config import settings

    monkeypatch.setattr(settings, "password_hibp_check_enabled", True)
    monkeypatch.setattr(passwords, "pwned_count", lambda p, **kw: 0)

    response = await client.post(
        "/api/auth/register",
        json={
            "org_name": "Clean Co",
            "domain": "clean.example",
            "email": "owner@clean.example",
            "password": "glacier-tumbling-vault-19",
        },
    )
    assert response.status_code == 201, response.text


@pytest.mark.anyio
async def test_password_change_checks_the_breach_corpus_only_after_auth(client, monkeypatch):
    """The endpoint must not be a free breach oracle for an unauthenticated caller.

    If the corpus lookup ran before the current-password check, anyone holding
    a stolen access token — or hitting the endpoint with a wrong current
    password — could test arbitrary strings against HIBP through us.
    """
    from config import settings

    register = {
        "org_name": "Order Co",
        "domain": "order.example",
        "email": "owner@order.example",
        "password": "glacier-tumbling-vault-19",
    }
    assert (await client.post("/api/auth/register", json=register)).status_code == 201
    token = (
        await client.post(
            "/api/auth/login",
            json={"email": register["email"], "password": register["password"]},
        )
    ).json()["access_token"]

    monkeypatch.setattr(settings, "password_hibp_check_enabled", True)
    calls = []

    def counting(password, **kwargs):
        calls.append(password)
        return 9_999

    monkeypatch.setattr(passwords, "pwned_count", counting)

    # Wrong current password: rejected on credentials, corpus never consulted.
    response = await client.post(
        "/api/auth/password",
        json={"current_password": "not-the-password", "new_password": "probe-target-value-1"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 400
    assert calls == [], "breach lookup ran before the current password was verified"
