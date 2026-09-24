"""Domain ownership verification.

These tests guard the boundary that makes this platform safe to run on the public
internet. Registration is open, so without a proof-of-ownership step any account
could name a domain it does not own and have the workers port-scan it. The
assertions worth reading twice are:

* a freshly registered organisation can scan **nothing** (``verified_domains``
  is empty, and the primary domain from the signup form grants no authority);
* one organisation's token is useless to another, even for the same domain;
* "no TXT record" and "could not reach DNS" produce different messages, because
  telling someone their record is missing when the resolver actually timed out
  sends them to fix something that is not broken.

The network is faked at the resolver, not at ``check_domain_token``, so the real
TXT parsing and the real exception-to-message mapping are both exercised.
"""

from __future__ import annotations

import pytest

import dns.exception
import dns.resolver
from core.dns_verify import check_domain_token, lookup_txt
from models.domain_verification import APEX_PREFIX, CHALLENGE_LABEL

pytestmark = pytest.mark.asyncio

DOMAINS = "/api/auth/organisation/domains"
ORGANISATION = "/api/auth/organisation"
PASSWORD = "correct-horse-battery-staple-7"


# --- fake DNS ---------------------------------------------------------------


class _Rdata:
    """One TXT rdata. ``strings`` is a list of bytes, as dnspython returns it."""

    def __init__(self, *chunks: bytes) -> None:
        self.strings = list(chunks)


class _FakeResolver:
    """A resolver backed by a dict instead of the network.

    A name mapped to a list yields TXT records; a name mapped to an exception
    raises it; a name that is absent raises NXDOMAIN. ``queries`` records the
    lookups in order, so a test can assert the apex was never consulted.
    """

    def __init__(self, zone: dict[str, object] | None = None) -> None:
        self.zone = zone or {}
        self.queries: list[str] = []

    async def resolve(self, name: str, rdtype: str):
        assert rdtype == "TXT", f"unexpected query type {rdtype}"
        self.queries.append(name)
        entry = self.zone.get(name)
        if entry is None:
            raise dns.resolver.NXDOMAIN
        if isinstance(entry, BaseException) or (
            isinstance(entry, type) and issubclass(entry, BaseException)
        ):
            raise entry
        return [v if isinstance(v, _Rdata) else _Rdata(str(v).encode()) for v in entry]


def _patch_dns(monkeypatch, zone: dict[str, object]) -> _FakeResolver:
    """Point the route's DNS check at ``zone``.

    Wraps the real ``check_domain_token`` with a fixed resolver rather than
    replacing it, so the challenge-name construction, the apex fallback and the
    failure messages are all the production code paths.
    """
    import routes.domains as route

    resolver = _FakeResolver(zone)

    async def _check(domain: str, token: str, _resolver=None):
        return await check_domain_token(domain, token, resolver)

    monkeypatch.setattr(route, "check_domain_token", _check)
    return resolver


# --- helpers ----------------------------------------------------------------


async def _register(client, slug: str, domain: str) -> dict:
    body = {
        "org_name": f"{slug} corp",
        "domain": domain,
        "email": f"owner@{domain}",
        "password": PASSWORD,
        "full_name": f"{slug} owner",
    }
    resp = await client.post("/api/auth/register", json=body)
    assert resp.status_code == 201, resp.text
    return {
        "headers": {"Authorization": f"Bearer {resp.json()['access_token']}"},
        "domain": domain,
    }


async def _claims(client, ctx: dict) -> list[dict]:
    resp = await client.get(DOMAINS, headers=ctx["headers"])
    assert resp.status_code == 200, resp.text
    return resp.json()["items"]


async def _only_claim(client, ctx: dict) -> dict:
    items = await _claims(client, ctx)
    assert len(items) == 1, items
    return items[0]


async def _verified_domains(client, ctx: dict) -> list[str]:
    resp = await client.get(ORGANISATION, headers=ctx["headers"])
    assert resp.status_code == 200, resp.text
    return resp.json()["verified_domains"]


@pytest.fixture
async def org(client) -> dict:
    return await _register(client, "alpha", "alpha-corp.example")


# --- registration -----------------------------------------------------------


async def test_registration_grants_no_scanning_authority(client, org):
    """The domain typed at signup is a claim, not a permission.

    This is the regression test for the original hole: registration used to write
    ``verified_domains=[body.domain]``, so an attacker signing up as
    ``microsoft.com`` was immediately authorised to scan it.
    """
    assert await _verified_domains(client, org) == []

    claim = await _only_claim(client, org)
    assert claim["domain"] == org["domain"]
    assert claim["status"] == "pending"
    assert claim["verified_at"] is None


async def test_registration_leaves_the_challenge_ready_to_publish(client, org):
    claim = await _only_claim(client, org)
    assert claim["record_name"] == f"{CHALLENGE_LABEL}.{org['domain']}"
    assert claim["record_value"]
    # The apex fallback is offered alongside it, for panels that will not create
    # an underscore label.
    assert claim["apex_record_name"] == org["domain"]
    assert claim["apex_record_value"] == f"{APEX_PREFIX}{claim['record_value']}"


# --- verifying --------------------------------------------------------------


async def test_dedicated_txt_record_verifies_and_grants_scope(client, org, monkeypatch):
    claim = await _only_claim(client, org)
    resolver = _patch_dns(
        monkeypatch, {f"{CHALLENGE_LABEL}.{org['domain']}": [claim["record_value"]]}
    )

    resp = await client.post(f"{DOMAINS}/{claim['id']}/verify", headers=org["headers"])
    assert resp.status_code == 200, resp.text
    assert resp.json()["verified"] is True

    # The row and the denormalised cache must agree — a VERIFIED claim whose
    # domain never reached verified_domains is an org that proved ownership and
    # still cannot scan.
    assert await _verified_domains(client, org) == [org["domain"]]
    assert (await _only_claim(client, org))["status"] == "verified"

    # One query: the apex is only consulted when the dedicated label misses.
    assert resolver.queries == [f"{CHALLENGE_LABEL}.{org['domain']}"]


async def test_verified_claim_stops_advertising_its_token(client, org, monkeypatch):
    claim = await _only_claim(client, org)
    _patch_dns(monkeypatch, {f"{CHALLENGE_LABEL}.{org['domain']}": [claim["record_value"]]})
    await client.post(f"{DOMAINS}/{claim['id']}/verify", headers=org["headers"])

    verified = await _only_claim(client, org)
    assert verified["record_value"] is None
    assert verified["record_name"] is None


async def test_apex_fallback_verifies_alongside_unrelated_txt_records(
    client, org, monkeypatch
):
    """A crowded apex RRset must not defeat the check."""
    claim = await _only_claim(client, org)
    resolver = _patch_dns(
        monkeypatch,
        {
            org["domain"]: [
                "v=spf1 include:_spf.example.net -all",
                "google-site-verification=abc123",
                f"{APEX_PREFIX}{claim['record_value']}",
            ]
        },
    )

    resp = await client.post(f"{DOMAINS}/{claim['id']}/verify", headers=org["headers"])
    assert resp.json()["verified"] is True
    assert await _verified_domains(client, org) == [org["domain"]]
    # Dedicated label first, apex second.
    assert resolver.queries == [f"{CHALLENGE_LABEL}.{org['domain']}", org["domain"]]


async def test_split_txt_character_strings_are_joined(client, org, monkeypatch):
    """Some panels wrap long values into multiple character-strings."""
    claim = await _only_claim(client, org)
    token = claim["record_value"]
    head, tail = token[:10].encode(), token[10:].encode()
    _patch_dns(monkeypatch, {f"{CHALLENGE_LABEL}.{org['domain']}": [_Rdata(head, tail)]})

    resp = await client.post(f"{DOMAINS}/{claim['id']}/verify", headers=org["headers"])
    assert resp.json()["verified"] is True


async def test_wrong_value_is_reported_as_a_stale_record(client, org, monkeypatch):
    claim = await _only_claim(client, org)
    _patch_dns(
        monkeypatch, {f"{CHALLENGE_LABEL}.{org['domain']}": ["a-token-from-last-week"]}
    )

    resp = await client.post(f"{DOMAINS}/{claim['id']}/verify", headers=org["headers"])
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["verified"] is False
    assert "none matched" in body["detail"]

    assert await _verified_domains(client, org) == []
    failed = await _only_claim(client, org)
    assert failed["status"] == "failed"
    assert failed["last_error"]
    # FAILED is not terminal: the same claim and token can be retried.
    assert failed["record_value"] == claim["record_value"]


async def test_missing_record_and_unreachable_dns_are_different_messages(
    client, org, monkeypatch
):
    """The distinction this whole module exists to preserve.

    NXDOMAIN is an authoritative "nothing here" and means go create the record.
    A timeout means we could not find out, and telling the user their record is
    missing would send them to fix DNS that may be configured perfectly.
    """
    claim = await _only_claim(client, org)
    url = f"{DOMAINS}/{claim['id']}/verify"

    _patch_dns(monkeypatch, {})  # every name NXDOMAINs
    missing = (await client.post(url, headers=org["headers"])).json()["detail"]
    assert "No TXT record found" in missing

    _patch_dns(
        monkeypatch,
        {
            f"{CHALLENGE_LABEL}.{org['domain']}": dns.exception.Timeout,
            org["domain"]: dns.exception.Timeout,
        },
    )
    unreachable = (await client.post(url, headers=org["headers"])).json()["detail"]
    assert "Could not check DNS" in unreachable
    assert "No TXT record found" not in unreachable
    assert missing != unreachable


async def test_verifying_an_already_verified_domain_skips_dns(client, org, monkeypatch):
    claim = await _only_claim(client, org)
    resolver = _patch_dns(
        monkeypatch, {f"{CHALLENGE_LABEL}.{org['domain']}": [claim["record_value"]]}
    )
    await client.post(f"{DOMAINS}/{claim['id']}/verify", headers=org["headers"])
    before = len(resolver.queries)

    resp = await client.post(f"{DOMAINS}/{claim['id']}/verify", headers=org["headers"])
    assert resp.json()["verified"] is True
    assert len(resolver.queries) == before, "re-check should not spend a DNS query"


async def test_expired_token_is_rejected_and_rotated(client, org, monkeypatch):
    """A token that outlived its window must stop verifying.

    The old value, even published correctly, is no longer proof — the expiry
    exists so a token leaked once decays instead of working forever. The claim
    rotates to a fresh token so the user can publish the new value without
    deleting and re-adding the domain.
    """
    import uuid
    from datetime import timedelta

    from db.database import session_scope
    from models import DomainVerification
    from models.base import utcnow
    from models.domain_verification import TOKEN_TTL

    claim = await _only_claim(client, org)

    # Age the claim's token past its deadline.
    with session_scope() as session:
        row = session.get(DomainVerification, uuid.UUID(claim["id"]))
        row.token_expires_at = utcnow() - timedelta(seconds=1)
        session.commit()

    # The user publishes the (now expired) token correctly — and it must fail.
    _patch_dns(monkeypatch, {f"{CHALLENGE_LABEL}.{org['domain']}": [claim["record_value"]]})
    resp = await client.post(f"{DOMAINS}/{claim['id']}/verify", headers=org["headers"])
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["verified"] is False
    assert "expired" in body["detail"].lower()

    # A fresh token was issued, with a fresh deadline.
    refreshed = (await _only_claim(client, org))
    assert refreshed["record_value"] != claim["record_value"]
    assert refreshed["status"] == "pending"
    with session_scope() as session:
        row = session.get(DomainVerification, uuid.UUID(claim["id"]))
        assert row.token_expires_at > utcnow() + TOKEN_TTL - timedelta(minutes=1)

    # The old token is now useless even though it is still in DNS...
    _patch_dns(monkeypatch, {f"{CHALLENGE_LABEL}.{org['domain']}": [claim["record_value"]]})
    again = await client.post(f"{DOMAINS}/{claim['id']}/verify", headers=org["headers"])
    assert again.json()["verified"] is False

    # ...and the fresh one verifies.
    _patch_dns(
        monkeypatch, {f"{CHALLENGE_LABEL}.{org['domain']}": [refreshed["record_value"]]}
    )
    ok = await client.post(f"{DOMAINS}/{claim['id']}/verify", headers=org["headers"])
    assert ok.json()["verified"] is True
    assert await _verified_domains(client, org) == [org["domain"]]


# --- what a verified domain actually buys -----------------------------------


async def test_scope_follows_verification_not_the_signup_form(
    client, org, monkeypatch
):
    """End-to-end consequence, with the lab escape hatch closed.

    ``conftest`` turns ``ALLOW_ARBITRARY_TARGETS`` on so the rest of the suite can
    scan freely; here it is off, which is the production posture and the only way
    to observe the gate.
    """
    from config import settings

    monkeypatch.setattr(settings, "allow_arbitrary_targets", False)
    claim = await _only_claim(client, org)

    # Unverified: its own signup domain is out of scope.
    denied = await client.post(
        "/api/assets", json={"hostname": f"www.{org['domain']}"}, headers=org["headers"]
    )
    assert denied.status_code == 403, denied.text

    _patch_dns(monkeypatch, {f"{CHALLENGE_LABEL}.{org['domain']}": [claim["record_value"]]})
    await client.post(f"{DOMAINS}/{claim['id']}/verify", headers=org["headers"])

    # Verified: the domain and everything under it.
    allowed = await client.post(
        "/api/assets", json={"hostname": f"www.{org['domain']}"}, headers=org["headers"]
    )
    assert allowed.status_code in (200, 201), allowed.text

    # But not a lookalike that merely ends alike.
    lookalike = await client.post(
        "/api/assets",
        json={"hostname": f"not{org['domain']}"},
        headers=org["headers"],
    )
    assert lookalike.status_code == 403, lookalike.text


async def test_deleting_a_domain_revokes_its_authority(client, org, monkeypatch):
    claim = await _only_claim(client, org)
    _patch_dns(monkeypatch, {f"{CHALLENGE_LABEL}.{org['domain']}": [claim["record_value"]]})
    await client.post(f"{DOMAINS}/{claim['id']}/verify", headers=org["headers"])
    assert await _verified_domains(client, org) == [org["domain"]]

    resp = await client.delete(f"{DOMAINS}/{claim['id']}", headers=org["headers"])
    assert resp.status_code == 200, resp.text

    assert await _verified_domains(client, org) == []
    assert await _claims(client, org) == []


# --- cross-tenant -----------------------------------------------------------


async def test_one_orgs_token_is_useless_to_another(client, monkeypatch):
    """Two orgs may both claim a domain; each must prove control separately."""
    shared = "contested.example"
    a = await _register(client, "alpha", shared)
    b = await _register(client, "beta", "beta-corp.example")

    claim_a = await _only_claim(client, a)
    added = await client.post(DOMAINS, json={"domain": shared}, headers=b["headers"])
    assert added.status_code == 200, added.text
    claim_b = added.json()

    assert claim_a["record_value"] != claim_b["record_value"]

    # Only org A's token is published.
    _patch_dns(monkeypatch, {f"{CHALLENGE_LABEL}.{shared}": [claim_a["record_value"]]})

    denied = await client.post(f"{DOMAINS}/{claim_b['id']}/verify", headers=b["headers"])
    assert denied.json()["verified"] is False
    assert shared not in await _verified_domains(client, b)

    granted = await client.post(f"{DOMAINS}/{claim_a['id']}/verify", headers=a["headers"])
    assert granted.json()["verified"] is True
    assert await _verified_domains(client, a) == [shared]


async def test_another_orgs_claim_is_invisible_and_untouchable(client, monkeypatch):
    a = await _register(client, "alpha", "alpha-corp.example")
    b = await _register(client, "beta", "beta-corp.example")
    claim_a = await _only_claim(client, a)

    # Not listed for B...
    assert all(c["id"] != claim_a["id"] for c in await _claims(client, b))

    # ...and 404, not 403 — a 403 would confirm the id exists.
    _patch_dns(monkeypatch, {f"{CHALLENGE_LABEL}.{a['domain']}": [claim_a["record_value"]]})
    assert (
        await client.post(f"{DOMAINS}/{claim_a['id']}/verify", headers=b["headers"])
    ).status_code == 404
    assert (
        await client.delete(f"{DOMAINS}/{claim_a['id']}", headers=b["headers"])
    ).status_code == 404

    # Neither attempt touched it.
    still_there = await _only_claim(client, a)
    assert still_there["id"] == claim_a["id"]
    assert still_there["status"] == "pending"
    assert await _verified_domains(client, b) == []


# --- adding ----------------------------------------------------------------


async def test_re_adding_returns_the_same_claim_and_token(client, org):
    """Idempotent by design: re-adding must not invalidate a published record."""
    first = await _only_claim(client, org)
    resp = await client.post(DOMAINS, json={"domain": org["domain"]}, headers=org["headers"])
    assert resp.status_code == 200, resp.text
    assert resp.json()["id"] == first["id"]
    assert resp.json()["record_value"] == first["record_value"]
    assert len(await _claims(client, org)) == 1


async def test_domain_input_is_normalised(client, org):
    resp = await client.post(
        DOMAINS, json={"domain": "  HTTPS://WWW.Second.Example/path  "}, headers=org["headers"]
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["domain"] == "www.second.example"


@pytest.mark.parametrize(
    "domain",
    [
        "localhost",           # single label, and a forbidden name
        "nodot",               # single label
        "127.0.0.1",           # IP literal — a record has nowhere to live
        "8.8.8.8",             # public IP, still an address not a name
        "192.168.1.1",
        "com",                 # bare public suffix
        "co.uk",               # ...and a two-level one
        "box.local",           # internal-only suffix
        "svc.internal",
        "-bad.example.com",    # label may not start with a hyphen
        "a..example.com",      # empty label
    ],
)
async def test_unclaimable_domains_are_rejected(client, org, domain):
    """A verified public suffix would authorise scanning everything under it.

    ``in_scope`` is a suffix match, so ``com`` in ``verified_domains`` would put
    every ``.com`` host in scope. Nobody can place a TXT record on ``com``, so
    this is defence in depth, but it costs one frozenset lookup.
    """
    resp = await client.post(DOMAINS, json={"domain": domain}, headers=org["headers"])
    assert resp.status_code == 422, resp.text


async def test_registration_rejects_the_same_domains(client):
    """The signup form and the add-domain form must agree.

    They used to not: registration only checked for a dot, so an account could be
    created claiming ``co.uk`` or an IP address.
    """
    body = {
        "org_name": "sneaky",
        "domain": "co.uk",
        "email": "owner@sneaky.example",
        "password": PASSWORD,
    }
    resp = await client.post("/api/auth/register", json=body)
    assert resp.status_code == 422, resp.text


async def test_per_org_cap_is_enforced(client, org, monkeypatch):
    from config import settings

    # Registration already created one claim, so a cap of 2 leaves room for one.
    monkeypatch.setattr(settings, "max_verified_domains_per_org", 2)

    ok = await client.post(DOMAINS, json={"domain": "second.example"}, headers=org["headers"])
    assert ok.status_code == 200, ok.text

    full = await client.post(DOMAINS, json={"domain": "third.example"}, headers=org["headers"])
    assert full.status_code == 409, full.text
    assert "maximum" in full.json()["detail"]

    # The cap counts claims, not just verified ones — otherwise pending rows are
    # an unbounded way to make us hold tokens.
    assert len(await _claims(client, org)) == 2


async def test_the_cap_is_advertised_so_the_ui_need_not_hardcode_it(client, org):
    resp = await client.get(DOMAINS, headers=org["headers"])
    from config import settings

    assert resp.json()["limit"] == settings.max_verified_domains_per_org


# --- abuse limits -----------------------------------------------------------


async def test_verify_is_rate_limited_per_org(client, org, monkeypatch):
    """Each attempt sends outbound DNS, so this is an amplification vector."""
    import routes.domains as route
    from core.ratelimit import RateLimitRule

    monkeypatch.setattr(route, "DOMAIN_VERIFY_ORG", RateLimitRule("test:domain_verify", 2, 60))
    # A failing zone, so the claim never verifies and every call spends budget.
    _patch_dns(monkeypatch, {})

    claim = await _only_claim(client, org)
    url = f"{DOMAINS}/{claim['id']}/verify"

    assert (await client.post(url, headers=org["headers"])).status_code == 200
    assert (await client.post(url, headers=org["headers"])).status_code == 200
    assert (await client.post(url, headers=org["headers"])).status_code == 429


# --- roles ------------------------------------------------------------------


async def _invite(client, ctx: dict, role: str) -> dict:
    resp = await client.post(
        "/api/auth/users",
        json={"email": f"{role}@{ctx['domain']}", "password": PASSWORD, "role": role},
        headers=ctx["headers"],
    )
    assert resp.status_code in (200, 201), resp.text
    login = await client.post(
        "/api/auth/login", json={"email": f"{role}@{ctx['domain']}", "password": PASSWORD}
    )
    assert login.status_code == 200, login.text
    return {
        "headers": {"Authorization": f"Bearer {login.json()['access_token']}"},
        "domain": ctx["domain"],
    }


async def test_viewers_cannot_see_challenge_tokens(client, org):
    viewer = await _invite(client, org, "viewer")
    assert (await client.get(DOMAINS, headers=viewer["headers"])).status_code == 403


async def test_analysts_can_read_but_not_grant_scope(client, org):
    """Adding a domain is granting scanning authority; that is an admin action."""
    analyst = await _invite(client, org, "analyst")
    assert (await client.get(DOMAINS, headers=analyst["headers"])).status_code == 200

    claim = await _only_claim(client, org)
    assert (
        await client.post(DOMAINS, json={"domain": "second.example"}, headers=analyst["headers"])
    ).status_code == 403
    assert (
        await client.post(f"{DOMAINS}/{claim['id']}/verify", headers=analyst["headers"])
    ).status_code == 403
    assert (
        await client.delete(f"{DOMAINS}/{claim['id']}", headers=analyst["headers"])
    ).status_code == 403


async def test_domain_endpoints_require_authentication(client):
    assert (await client.get(DOMAINS)).status_code == 401
    assert (await client.post(DOMAINS, json={"domain": "x.example"})).status_code == 401


# --- the DNS layer on its own -----------------------------------------------


async def test_lookup_txt_reports_no_record_without_calling_it_an_error():
    """NXDOMAIN and NoAnswer are answers: the name has no TXT records."""
    for failure in (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        result = await lookup_txt("x.example", _FakeResolver({"x.example": failure}))
        assert result.resolved is True
        assert result.values == ()
        assert result.error is None


async def test_lookup_txt_reports_an_unreachable_resolver_as_an_error():
    for failure in (dns.exception.Timeout, dns.resolver.NoNameservers):
        result = await lookup_txt("x.example", _FakeResolver({"x.example": failure}))
        assert result.resolved is False
        assert result.error


async def test_lookup_txt_joins_and_trims_values():
    resolver = _FakeResolver({"x.example": [_Rdata(b"one-", b"two"), _Rdata(b"  spaced  ")]})
    result = await lookup_txt("x.example", resolver)
    assert result.values == ("one-two", "spaced")


async def test_check_domain_token_is_exact_not_substring():
    """A record containing the token as a prefix must not verify."""
    token = "abc123"
    resolver = _FakeResolver({f"{CHALLENGE_LABEL}.x.example": [f"{token}-extra"]})
    result = await check_domain_token("x.example", token, resolver)
    assert result.ok is False
