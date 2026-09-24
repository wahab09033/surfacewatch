"""Unit tests for the security-critical core.

These functions are what stop the platform from scanning infrastructure it has
no authorisation to touch, from duplicating findings on every re-scan, and from
accepting forged or misused tokens. They are pure, so they are tested directly
rather than through the API.
"""

from __future__ import annotations

import uuid

import pytest

from core.scoring import (
    MAX_RISK_SCORE,
    OutOfScopeError,
    assert_in_scope,
    in_scope,
    is_private_address,
    normalise_host,
    score_asset,
)
from core.security import (
    InvalidTokenError,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from models import Finding, Organisation, Severity, UserRole


# --- scope guard ------------------------------------------------------------


@pytest.mark.parametrize(
    "target",
    [
        "127.0.0.1",
        "localhost",
        "10.0.0.5",
        "192.168.1.1",
        "172.16.0.1",
        "169.254.169.254",  # cloud metadata endpoint — the classic SSRF pivot
        "0.0.0.0",
        "::1",
    ],
)
def test_private_and_reserved_targets_are_always_refused(target):
    """Even with the domain allow-listed, internal ranges stay off limits."""
    with pytest.raises(OutOfScopeError):
        assert_in_scope(target, ["example.com"])

    # And not even the lab escape hatch may reach them.
    with pytest.raises(OutOfScopeError):
        assert_in_scope(target, ["example.com"], allow_arbitrary=True)


@pytest.mark.parametrize(
    "target",
    [
        "[::1]:8080",           # bracketed IPv6 with a port
        "[fe80::1]",            # bracketed link-local
        "https://[::1]/admin",  # ...behind a scheme
        "http://user:pass@127.0.0.1:8080/x",  # credentials before the host
        "evil.com@127.0.0.1",   # in-scope name used as a userinfo decoy
        "foo.local",
        "svc.internal",
        "box.localhost",
        "LOCALHOST",
    ],
)
def test_internal_targets_in_url_forms_are_refused(target):
    """The loopback check must survive URL syntax, not just bare literals."""
    with pytest.raises(OutOfScopeError):
        assert_in_scope(target, ["example.com", "127.0.0.1"], allow_arbitrary=True)


def test_out_of_scope_domain_is_refused():
    with pytest.raises(OutOfScopeError):
        assert_in_scope("victim.com", ["example.com"])


def test_lookalike_domains_are_refused():
    """Suffix matching must not be fooled by a domain that merely ends alike."""
    for host in ("notexample.com", "example.com.evil.net", "fakeexample.com"):
        with pytest.raises(OutOfScopeError):
            assert_in_scope(host, ["example.com"])


def test_in_scope_targets_are_allowed():
    assert assert_in_scope("example.com", ["example.com"]) == "example.com"
    assert assert_in_scope("www.example.com", ["example.com"]) == "www.example.com"
    assert assert_in_scope("a.b.example.com", ["example.com"]) == "a.b.example.com"


def test_empty_target_is_refused():
    for value in ("", "   ", None):
        with pytest.raises(OutOfScopeError):
            assert_in_scope(value or "", ["example.com"])


def test_normalise_host_strips_scheme_port_and_case():
    assert normalise_host("HTTPS://WWW.Example.COM:8443/path?q=1") == "www.example.com"
    assert normalise_host("  example.com.  ") == "example.com"


def test_no_verified_domains_means_nothing_is_in_scope():
    """A fresh org with no verified domains cannot scan anything."""
    assert not in_scope("example.com", [])
    with pytest.raises(OutOfScopeError):
        assert_in_scope("example.com", [])


def test_all_domains_excludes_the_unverified_primary_domain():
    """``Organisation.domain`` is an identity, not a permission.

    It used to be included in ``all_domains`` unconditionally, which meant the
    domain typed into the open registration form was authorised for scanning
    before anyone proved they owned it. Verification is now the only way in.
    """
    org = Organisation(name="Acme", domain="acme.example", verified_domains=[])
    assert org.all_domains == []
    with pytest.raises(OutOfScopeError):
        assert_in_scope("acme.example", org.all_domains)


def test_all_domains_normalises_and_dedupes():
    """Scope matching is exact-suffix, so casing and trailing dots must not slip in."""
    org = Organisation(
        name="Acme",
        domain="acme.example",
        verified_domains=["ACME.example", "acme.example.", "", "other.example"],
    )
    assert org.all_domains == ["acme.example", "other.example"]
    assert in_scope("www.acme.example", org.all_domains)


def test_all_domains_tolerates_a_null_column():
    """An empty scope is a valid state, and no caller may fall back to ``domain``."""
    org = Organisation(name="Acme", domain="acme.example", verified_domains=None)
    assert org.all_domains == []


def test_is_private_address_allows_only_genuinely_routable_ips():
    """Documentation ranges are refused, not treated as public.

    ``203.0.113.0/24`` is TEST-NET-3 (RFC 5737) — reserved for examples, never
    a real destination. This test used it as its example of a public address
    until ``_EXTRA_UNSAFE_NETWORKS`` was added to cover special-use space, at
    which point the assertion was pinning the wrong behaviour.
    """
    assert not is_private_address("8.8.8.8")
    assert not is_private_address("93.184.216.34")
    assert is_private_address("10.1.2.3")
    assert is_private_address("203.0.113.10")


# --- finding deduplication --------------------------------------------------


def test_fingerprint_is_stable_across_rescans():
    """The same issue on the same asset must produce the same fingerprint."""
    asset = uuid.uuid4()
    a = Finding.build_fingerprint(asset_id=asset, title="Exposed Redis", port=6379)
    b = Finding.build_fingerprint(asset_id=asset, title="Exposed Redis", port=6379)
    assert a == b


def test_fingerprint_is_case_and_whitespace_insensitive():
    asset = uuid.uuid4()
    a = Finding.build_fingerprint(asset_id=asset, title="Exposed Redis")
    b = Finding.build_fingerprint(asset_id=asset, title="  exposed redis  ")
    assert a == b


def test_fingerprint_separates_distinct_issues():
    asset = uuid.uuid4()
    other = uuid.uuid4()
    base = Finding.build_fingerprint(asset_id=asset, title="Exposed Redis", port=6379)

    # Different port, different asset, and different issue must all differ.
    assert base != Finding.build_fingerprint(asset_id=asset, title="Exposed Redis", port=6380)
    assert base != Finding.build_fingerprint(asset_id=other, title="Exposed Redis", port=6379)
    assert base != Finding.build_fingerprint(asset_id=asset, title="Exposed Mongo", port=6379)


def test_fingerprint_prefers_cve_over_title():
    """Two scanners wording the same CVE differently must still dedupe."""
    asset = uuid.uuid4()
    a = Finding.build_fingerprint(asset_id=asset, title="nginx RCE", cve_id="CVE-2024-1234")
    b = Finding.build_fingerprint(
        asset_id=asset, title="Remote code execution in nginx", cve_id="CVE-2024-1234"
    )
    assert a == b


# --- risk scoring -----------------------------------------------------------

def test_score_is_capped():
    score = score_asset(findings=[Severity.CRITICAL] * 200, open_ports=list(range(1, 500)))
    assert score <= MAX_RISK_SCORE


def test_score_rises_with_severity():
    low = score_asset(findings=[Severity.LOW], open_ports=[])
    high = score_asset(findings=[Severity.CRITICAL], open_ports=[])
    assert high > low


def test_clean_asset_scores_zero():
    assert score_asset(findings=[], open_ports=[]) == 0.0


def test_risky_port_outweighs_expected_web_port():
    web = score_asset(findings=[], open_ports=[443])
    docker = score_asset(findings=[], open_ports=[2375])
    assert docker > web


# --- password hashing -------------------------------------------------------


def test_password_round_trip():
    h = hash_password("correct-horse-battery-staple-7")
    assert verify_password("correct-horse-battery-staple-7", h)
    assert not verify_password("wrong-password-9", h)


def test_hash_is_salted():
    """Two users with the same password must not share a hash."""
    assert hash_password("same-password-1") != hash_password("same-password-1")


def test_long_passwords_do_not_crash_bcrypt():
    """bcrypt truncates at 72 bytes; the wrapper must handle that, not raise."""
    long_pw = "A" * 200 + "1"
    h = hash_password(long_pw)
    assert verify_password(long_pw, h)


def test_multibyte_password_round_trip():
    pw = "пароль-🔐-secure-2024"
    assert verify_password(pw, hash_password(pw))


def test_verify_rejects_malformed_hash():
    """A corrupt stored hash must return False, never raise."""
    assert not verify_password("anything", "not-a-bcrypt-hash")


# --- tokens -----------------------------------------------------------------


def _ids():
    return uuid.uuid4(), uuid.uuid4()


def test_access_token_round_trip():
    uid, oid = _ids()
    token = create_access_token(
        user_id=uid, org_id=oid, role=UserRole.ANALYST, token_version=0
    )
    payload = decode_token(token, expect="access")
    assert payload.user_id == uid
    assert payload.org_id == oid


def test_refresh_token_cannot_be_used_as_access_token():
    """Type confusion between the two token kinds must be rejected."""
    uid, oid = _ids()
    refresh = create_refresh_token(
        user_id=uid, org_id=oid, role=UserRole.ANALYST, token_version=0
    )
    with pytest.raises(InvalidTokenError):
        decode_token(refresh, expect="access")


def test_access_token_cannot_be_used_as_refresh_token():
    uid, oid = _ids()
    access = create_access_token(
        user_id=uid, org_id=oid, role=UserRole.ANALYST, token_version=0
    )
    with pytest.raises(InvalidTokenError):
        decode_token(access, expect="refresh")


def test_tampered_token_is_rejected():
    uid, oid = _ids()
    token = create_access_token(
        user_id=uid, org_id=oid, role=UserRole.OWNER, token_version=0
    )
    tampered = token[:-4] + ("aaaa" if not token.endswith("aaaa") else "bbbb")
    with pytest.raises(InvalidTokenError):
        decode_token(tampered, expect="access")


def test_unsigned_token_is_rejected():
    """A token re-encoded with alg=none must not be trusted."""
    import base64
    import json

    def b64(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    uid, oid = _ids()
    forged = (
        b64({"alg": "none", "typ": "JWT"})
        + "."
        + b64({"sub": str(uid), "org_id": str(oid), "role": "owner", "tv": 0, "type": "access"})
        + "."
    )
    with pytest.raises(InvalidTokenError):
        decode_token(forged, expect="access")


def test_token_carries_org_and_role():
    """org_id in the token is what every isolation check keys off."""
    uid, oid = _ids()
    payload = decode_token(
        create_access_token(user_id=uid, org_id=oid, role=UserRole.VIEWER, token_version=3),
        expect="access",
    )
    assert payload.org_id == oid
    assert payload.role == UserRole.VIEWER
    assert payload.token_version == 3


# --- role hierarchy ---------------------------------------------------------


def test_role_ranking_is_ordered():
    assert UserRole.OWNER.rank > UserRole.ADMIN.rank
    assert UserRole.ADMIN.rank > UserRole.ANALYST.rank
    assert UserRole.ANALYST.rank > UserRole.VIEWER.rank


def test_at_least_gates_privilege():
    assert UserRole.OWNER.at_least(UserRole.ADMIN)
    assert UserRole.ADMIN.at_least(UserRole.ADMIN)
    assert not UserRole.VIEWER.at_least(UserRole.ANALYST)


def test_severity_from_cvss_boundaries():
    assert Severity.from_cvss(9.8) is Severity.CRITICAL
    assert Severity.from_cvss(7.5) is Severity.HIGH
    assert Severity.from_cvss(5.0) is Severity.MEDIUM
    assert Severity.from_cvss(0.0) is Severity.INFO
    assert Severity.from_cvss(None) is Severity.INFO


# --- connection strings -----------------------------------------------------


def test_database_urls_percent_encode_the_password():
    """A generated password containing @ or # must not reshape the URL.

    An unencoded @ truncates the host — the driver would connect to whatever
    followed it — and a # discards the rest of the string. Both fail in ways
    that look like a network problem rather than a quoting bug.
    """
    from sqlalchemy.engine import make_url

    from config import Settings

    settings = Settings(
        jwt_secret="x" * 40,
        postgres_user="sw@user",
        postgres_password="p@ss:w/rd#1?2",
        postgres_host="db.internal",
        postgres_port=5432,
        postgres_db="surfacewatch",
    )

    for url in (settings.database_url, settings.sync_database_url):
        # Asserted through SQLAlchemy's own parser rather than urlsplit,
        # because make_url is what actually consumes these strings — and it
        # unquotes the credentials on the way through, which is the half of the
        # round trip that makes the encoding correct rather than merely safe.
        parsed = make_url(url)
        assert parsed.host == "db.internal", url
        assert parsed.port == 5432
        assert parsed.database == "surfacewatch"
        assert parsed.username == "sw@user"
        assert parsed.password == "p@ss:w/rd#1?2"
        # And the structural characters must not appear raw in the credentials.
        credentials = url.split("//", 1)[1].split("@db.internal", 1)[0]
        assert "#" not in credentials
        assert "?" not in credentials


def test_a_simple_password_is_left_readable():
    from config import Settings

    settings = Settings(
        jwt_secret="x" * 40,
        postgres_user="surfacewatch",
        postgres_password="simple-password-1",
        postgres_host="localhost",
        postgres_port=5432,
        postgres_db="surfacewatch",
    )
    assert (
        settings.database_url
        == "postgresql+asyncpg://surfacewatch:simple-password-1@localhost:5432/surfacewatch"
    )
