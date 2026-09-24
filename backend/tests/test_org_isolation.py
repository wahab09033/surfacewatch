"""Multi-tenant isolation tests.

The product promise is that a user can only ever see their own organisation's
data. That is enforced per-query rather than by a single chokepoint, so it is
worth testing directly against a real Postgres instance: these tests stand up
two organisations, give each real assets/scans/findings, and then assert that
tenant B cannot read, mutate, enumerate, or probe tenant A's rows through any
route on the API.

Run with:  pytest tests/ -v
"""

from __future__ import annotations

import uuid

import pytest


pytestmark = pytest.mark.asyncio


# --- fixtures ---------------------------------------------------------------


@pytest.fixture
async def org_a(client) -> dict:
    return await _register(client, "alpha", "alpha-corp.example")


@pytest.fixture
async def org_b(client) -> dict:
    return await _register(client, "beta", "beta-corp.example")


async def _register(client, slug: str, domain: str) -> dict:
    """Create an organisation + owner and return its auth context."""
    body = {
        "org_name": f"{slug} corp",
        "domain": domain,
        "email": f"owner@{domain}",
        "password": "correct-horse-battery-staple-7",
        "full_name": f"{slug} owner",
    }
    resp = await client.post("/api/auth/register", json=body)
    assert resp.status_code in (200, 201), resp.text
    tokens = resp.json()

    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    me = await client.get("/api/auth/me", headers=headers)
    assert me.status_code == 200, me.text

    return {
        "headers": headers,
        "org_id": me.json()["org_id"],
        "user_id": me.json()["id"],
        "domain": domain,
        "email": body["email"],
        "password": body["password"],
    }


async def _seed(client, ctx: dict, label: str = "www") -> dict:
    """Give an org one asset and one finding, and return their ids.

    `label` varies the hostname so a test can seed an org more than once
    without tripping the per-org unique hostname constraint.
    """
    hostname = f"{label}.{ctx['domain']}"
    asset = await client.post(
        "/api/assets",
        headers=ctx["headers"],
        json={"hostname": hostname, "ip": "203.0.113.10"},
    )
    assert asset.status_code in (200, 201), asset.text
    asset_id = asset.json()["id"]

    finding = await client.post(
        "/api/findings",
        headers=ctx["headers"],
        json={
            "asset_id": asset_id,
            "title": f"Secret issue for {hostname}",
            "severity": "high",
            "description": "tenant-private detail",
        },
    )
    assert finding.status_code in (200, 201), finding.text

    return {"asset_id": asset_id, "finding_id": finding.json()["id"], "hostname": hostname}


# --- tests ------------------------------------------------------------------


async def test_register_isolates_orgs(org_a, org_b):
    """Two registrations must land in genuinely separate organisations."""
    assert org_a["org_id"] != org_b["org_id"]


async def test_domain_claims_do_not_leak(client, org_a, org_b):
    """A domain claim carries a challenge token, so it is tenant-private.

    Registration creates one PENDING claim per org. Neither may appear in the
    other's listing, and a claim id from A must 404 rather than 403 for B — the
    full add/verify/delete boundary is covered in test_domain_verification.py.
    """
    domains = "/api/auth/organisation/domains"

    a_claims = (await client.get(domains, headers=org_a["headers"])).json()["items"]
    b_claims = (await client.get(domains, headers=org_b["headers"])).json()["items"]
    assert [c["domain"] for c in a_claims] == [org_a["domain"]]
    assert [c["domain"] for c in b_claims] == [org_b["domain"]]

    a_id = a_claims[0]["id"]
    stolen = await client.post(f"{domains}/{a_id}/verify", headers=org_b["headers"])
    absent = await client.post(f"{domains}/{uuid.uuid4()}/verify", headers=org_b["headers"])
    assert stolen.status_code == 404
    assert stolen.json() == absent.json()

    assert (
        await client.delete(f"{domains}/{a_id}", headers=org_b["headers"])
    ).status_code == 404
    assert (await client.get(domains, headers=org_a["headers"])).json()["items"]


async def test_asset_lists_do_not_leak(client, org_a, org_b):
    a = await _seed(client, org_a)
    await _seed(client, org_b)

    listing = await client.get("/api/assets", headers=org_b["headers"])
    assert listing.status_code == 200
    hostnames = [item["hostname"] for item in listing.json()["items"]]

    assert f"www.{org_b['domain']}" in hostnames
    assert f"www.{org_a['domain']}" not in hostnames
    assert all(item["id"] != a["asset_id"] for item in listing.json()["items"])


async def test_cross_org_asset_read_is_404(client, org_a, org_b):
    """A valid id from another tenant must look identical to a missing one."""
    a = await _seed(client, org_a)

    stolen = await client.get(f"/api/assets/{a['asset_id']}", headers=org_b["headers"])
    absent = await client.get(f"/api/assets/{uuid.uuid4()}", headers=org_b["headers"])

    assert stolen.status_code == 404
    # Identical status AND body, so the response cannot be used to test whether
    # an id exists in some other organisation.
    assert stolen.status_code == absent.status_code
    assert stolen.json() == absent.json()


async def test_cross_org_asset_mutation_is_refused(client, org_a, org_b):
    a = await _seed(client, org_a)

    patched = await client.patch(
        f"/api/assets/{a['asset_id']}",
        headers=org_b["headers"],
        json={"notes": "pwned by tenant B"},
    )
    assert patched.status_code == 404

    deleted = await client.delete(f"/api/assets/{a['asset_id']}", headers=org_b["headers"])
    assert deleted.status_code == 404

    # ...and the row is untouched from its owner's perspective.
    still_there = await client.get(f"/api/assets/{a['asset_id']}", headers=org_a["headers"])
    assert still_there.status_code == 200
    assert still_there.json()["notes"] != "pwned by tenant B"


async def test_findings_do_not_leak(client, org_a, org_b):
    a = await _seed(client, org_a)
    await _seed(client, org_b)

    listing = await client.get("/api/findings", headers=org_b["headers"])
    assert listing.status_code == 200
    titles = [f["title"] for f in listing.json()["items"]]
    assert not any(org_a["domain"] in t for t in titles)

    direct = await client.get(f"/api/findings/{a['finding_id']}", headers=org_b["headers"])
    assert direct.status_code == 404

    triage = await client.patch(
        f"/api/findings/{a['finding_id']}",
        headers=org_b["headers"],
        json={"status": "false_positive"},
    )
    assert triage.status_code == 404


async def test_finding_filters_cannot_pivot_across_orgs(client, org_a, org_b):
    """Filtering by another tenant's asset_id must not surface their findings."""
    a = await _seed(client, org_a)

    resp = await client.get(
        "/api/findings",
        headers=org_b["headers"],
        params={"asset_id": a["asset_id"]},
    )
    assert resp.status_code in (200, 404)
    if resp.status_code == 200:
        assert resp.json()["items"] == []


async def test_scans_do_not_leak(client, org_a, org_b):
    """A scan is only visible to its own org, including its logs."""
    created = await client.post(
        "/api/scans",
        headers=org_a["headers"],
        json={"target": org_a["domain"], "config": {"passive_only": True}},
    )
    assert created.status_code in (200, 201, 202), created.text
    scan_id = created.json()["id"]

    listing = await client.get("/api/scans", headers=org_b["headers"])
    assert listing.status_code == 200
    assert all(s["id"] != scan_id for s in listing.json()["items"])

    assert (await client.get(f"/api/scans/{scan_id}", headers=org_b["headers"])).status_code == 404
    assert (
        await client.get(f"/api/scans/{scan_id}/logs", headers=org_b["headers"])
    ).status_code == 404
    assert (
        await client.post(f"/api/scans/{scan_id}/cancel", headers=org_b["headers"])
    ).status_code == 404

    # The owner can still see it.
    assert (await client.get(f"/api/scans/{scan_id}", headers=org_a["headers"])).status_code == 200


async def test_user_directory_is_org_scoped(client, org_a, org_b):
    users = await client.get("/api/auth/users", headers=org_b["headers"])
    assert users.status_code == 200
    emails = [u["email"] for u in users.json()]
    assert org_b["email"] in emails
    assert org_a["email"] not in emails


async def test_cross_org_user_deactivation_is_refused(client, org_a, org_b):
    """An owner of B must not be able to disable a user in A."""
    resp = await client.delete(
        f"/api/auth/users/{org_a['user_id']}", headers=org_b["headers"]
    )
    assert resp.status_code == 404

    # A's owner can still authenticate.
    login = await client.post(
        "/api/auth/login",
        json={"email": org_a["email"], "password": org_a["password"]},
    )
    assert login.status_code == 200


async def test_dashboard_and_stats_are_org_scoped(client, org_a, org_b):
    await _seed(client, org_a, "www")
    await _seed(client, org_a, "api")

    dash = await client.get("/api/reports/dashboard", headers=org_b["headers"])
    assert dash.status_code == 200
    body = dash.json()
    assert body.get("total_assets", 0) == 0
    assert body.get("total_findings", body.get("open_findings", 0)) == 0

    stats = await client.get("/api/assets/stats", headers=org_b["headers"])
    assert stats.status_code == 200
    assert stats.json().get("total", 0) == 0


async def test_cross_org_report_download_is_refused(client, org_a, org_b):
    created = await client.post(
        "/api/reports", headers=org_a["headers"], json={"title": "A's confidential report"}
    )
    assert created.status_code in (200, 201, 202), created.text
    report_id = created.json()["id"]

    assert (
        await client.get(f"/api/reports/{report_id}", headers=org_b["headers"])
    ).status_code == 404
    assert (
        await client.get(f"/api/reports/{report_id}/download", headers=org_b["headers"])
    ).status_code == 404
    assert (
        await client.delete(f"/api/reports/{report_id}", headers=org_b["headers"])
    ).status_code == 404

    listing = await client.get("/api/reports", headers=org_b["headers"])
    assert listing.status_code == 200
    items = listing.json()
    items = items["items"] if isinstance(items, dict) else items
    assert all(r["id"] != report_id for r in items)


# --- token-level isolation --------------------------------------------------


async def test_unauthenticated_access_is_refused(client):
    for path in ("/api/assets", "/api/findings", "/api/scans", "/api/reports/dashboard"):
        resp = await client.get(path)
        assert resp.status_code in (401, 403), f"{path} returned {resp.status_code}"


async def test_garbage_and_tampered_tokens_are_refused(client, org_a):
    real = org_a["headers"]["Authorization"].split(" ", 1)[1]

    # Flipping a character in the signature must invalidate the token.
    tampered = real[:-3] + ("aaa" if not real.endswith("aaa") else "bbb")

    for token in ("garbage", "a.b.c", tampered):
        resp = await client.get("/api/assets", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code in (401, 403), f"accepted token {token!r}"


async def test_password_change_revokes_existing_tokens(client, org_a):
    """token_version is embedded in the JWT, so old tokens must stop working."""
    old = org_a["headers"]

    changed = await client.post(
        "/api/auth/password",
        headers=old,
        json={
            "current_password": org_a["password"],
            "new_password": "an-entirely-different-passphrase-9",
        },
    )
    assert changed.status_code == 200, changed.text

    stale = await client.get("/api/auth/me", headers=old)
    assert stale.status_code in (401, 403)


# --- the Finding -> Asset join ----------------------------------------------
#
# The endpoints denormalise ``asset_hostname`` by looking the asset up from the
# finding's asset_id. That is only safe if a Finding can never point at another
# org's Asset. Every write path checks it, but the foreign key targets
# ``assets.id`` with no composite constraint on org_id, so the database does not
# enforce it — one bad row from a migration, a fixup script, or a future code
# path would turn into a hostname disclosure. These tests plant exactly that row
# and assert the join refuses to resolve it.


async def _plant_cross_org_finding(org_a: dict, org_b: dict) -> tuple[str, str]:
    """An asset owned by B, with a finding owned by A pointing at it."""
    from db.database import AsyncSessionLocal
    from models import Asset, Finding
    from models.base import AssetStatus, FindingStatus, Severity

    async with AsyncSessionLocal() as db:
        secret = Asset(
            org_id=uuid.UUID(org_b["org_id"]),
            hostname="secret.beta-corp.internal",
            status=AssetStatus.ACTIVE,
        )
        db.add(secret)
        await db.flush()

        planted = Finding(
            org_id=uuid.UUID(org_a["org_id"]),
            asset_id=secret.id,
            title="planted cross-org reference",
            severity=Severity.HIGH,
            status=FindingStatus.OPEN,
            fingerprint="test-planted-cross-org",
        )
        db.add(planted)
        await db.commit()
        return str(planted.id), str(secret.id)


async def test_cross_org_finding_does_not_leak_asset_hostname(client, org_a, org_b):
    finding_id, asset_id = await _plant_cross_org_finding(org_a, org_b)

    detail = await client.get(f"/api/findings/{finding_id}", headers=org_a["headers"])
    assert detail.status_code == 200, detail.text
    assert detail.json().get("asset_hostname") is None, (
        "detail view resolved another org's hostname"
    )

    listing = await client.get("/api/findings", headers=org_a["headers"])
    assert listing.status_code == 200
    assert "secret.beta-corp.internal" not in listing.text, (
        "list view resolved another org's hostname"
    )

    # The asset itself is still unreachable directly, as it always was.
    direct = await client.get(f"/api/assets/{asset_id}", headers=org_a["headers"])
    assert direct.status_code == 404


async def test_triage_response_does_not_leak_asset_hostname(client, org_a, org_b):
    """PATCH rebuilds the same denormalised field, from the same lookup."""
    finding_id, _ = await _plant_cross_org_finding(org_a, org_b)

    resp = await client.patch(
        f"/api/findings/{finding_id}",
        headers=org_a["headers"],
        json={"notes": "triaged"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json().get("asset_hostname") is None, (
        "triage response resolved another org's hostname"
    )


async def test_dashboard_does_not_leak_asset_hostname(client, org_a, org_b):
    """The same join again, in the report dashboard's recent-findings block."""
    await _plant_cross_org_finding(org_a, org_b)

    resp = await client.get("/api/reports/dashboard", headers=org_a["headers"])
    assert resp.status_code == 200, resp.text
    assert "secret.beta-corp.internal" not in resp.text, (
        "dashboard resolved another org's hostname"
    )
