"""End-to-end HTTP test against a running API.

Not a substitute for the pytest suite — this drives the real ASGI server over a
real socket against real Postgres, which is the layer the unit tests replace with
fixtures. The point of interest is org isolation: two tenants are created and
each is then asked for the other's records by id, which is the only way to prove
the scoping holds when the id is known and valid.

Usage:  python tests/e2e_live.py [base_url]
Assumes a server on 127.0.0.1:8000 with a database it may write to.
"""

import json
import sys
import urllib.error
import urllib.request
import uuid

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
# Suffix so the script is re-runnable against the same database without
# tripping the duplicate-email 409 on the second pass.
RUN = uuid.uuid4().hex[:8]
PW = "correct-horse-battery-7-staple"

ok, fail = 0, 0


def call(method, path, token=None, body=None):
    req = urllib.request.Request(BASE + path, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    data = json.dumps(body).encode() if body is not None else None
    try:
        with urllib.request.urlopen(req, data, timeout=30) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw or b"{}")
        except json.JSONDecodeError:
            return e.code, {"raw": raw[:300].decode(errors="replace")}


def check(label, got, want):
    global ok, fail
    if got == want:
        ok += 1
        print(f"  PASS  {label}")
    else:
        fail += 1
        print(f"  FAIL  {label}\n          got  {got!r}\n          want {want!r}")


def domain(tag):
    return f"{tag}-{RUN}.example"


print(f"=== register two independent orgs (run {RUN}) ===")
tok = {}
for tag in ("alpha", "bravo"):
    status, res = call(
        "POST",
        "/api/auth/register",
        body={
            "org_name": f"{tag.title()} Corp",
            "domain": domain(tag),
            "email": f"owner@{domain(tag)}",
            "password": PW,
            "full_name": f"{tag.title()} Owner",
        },
    )
    check(f"register {tag}", status, 201)
    if status != 201:
        print("    ->", res)
        sys.exit(1)
    check(f"{tag} gets an access+refresh pair", sorted(res)[:3], ["access_token", "expires_in", "refresh_token"])
    tok[tag] = res["access_token"]
    if tag == "alpha":
        alpha_refresh = res["refresh_token"]

print("\n=== credentials ===")
status, res = call("POST", "/api/auth/login", body={"email": f"owner@{domain('alpha')}", "password": PW})
check("login with correct password", status, 200)
status, _ = call("POST", "/api/auth/login", body={"email": f"owner@{domain('alpha')}", "password": "wrong-password-1"})
check("login with wrong password -> 401", status, 401)
status, _ = call("POST", "/api/auth/login", body={"email": f"nobody@{domain('alpha')}", "password": PW})
check("login unknown account -> 401", status, 401)
status, res = call("POST", "/api/auth/refresh", body={"refresh_token": alpha_refresh})
check("refresh rotates tokens", status, 200)
status, _ = call("POST", "/api/auth/refresh", body={"refresh_token": tok["alpha"]})
check("access token rejected at /refresh -> 401", status, 401)
status, res = call("GET", "/api/auth/me", token=tok["alpha"])
check("/me returns the owner", (status, res.get("role")), (200, "owner"))
check("/me never leaks a password hash", "password_hash" in json.dumps(res), False)
status, _ = call("GET", "/api/assets")
check("no token -> 401", status, 401)
status, _ = call("GET", "/api/assets", token="not.a.real.token")
check("garbage token -> 401", status, 401)

status, res = call("GET", "/api/auth/organisation", token=tok["alpha"])
check("org endpoint omits the raw webhook", "slack_webhook_url" in json.dumps(res), False)
check("org endpoint exposes only the configured flag", res.get("slack_webhook_configured"), False)

print("\n=== each org creates one asset ===")
asset = {}
for tag in ("alpha", "bravo"):
    status, res = call("POST", "/api/assets", token=tok[tag], body={"hostname": f"api.{domain(tag)}", "ip": "203.0.113.10"})
    check(f"create asset {tag}", status, 201)
    if status != 201:
        print("    ->", res)
        sys.exit(1)
    asset[tag] = res["id"]

print("\n=== each org records one finding ===")
finding = {}
for tag in ("alpha", "bravo"):
    status, res = call(
        "POST",
        "/api/findings",
        token=tok[tag],
        body={
            "asset_id": asset[tag],
            "title": f"{tag} exposure",
            "cve_id": "CVE-2024-6387",
            "cvss_score": 8.1,
        },
    )
    check(f"create finding {tag}", status, 201)
    if status != 201:
        print("    ->", res)
        sys.exit(1)
    finding[tag] = res["id"]

print("\n=== ORG ISOLATION: alpha holds valid ids belonging to bravo ===")
a = tok["alpha"]
for label, method, path, body in [
    ("GET    bravo's asset", "GET", f"/api/assets/{asset['bravo']}", None),
    ("PATCH  bravo's asset", "PATCH", f"/api/assets/{asset['bravo']}", {"notes": "owned"}),
    ("DELETE bravo's asset", "DELETE", f"/api/assets/{asset['bravo']}", None),
    ("GET    bravo's asset findings", "GET", f"/api/assets/{asset['bravo']}/findings", None),
    ("GET    bravo's finding", "GET", f"/api/findings/{finding['bravo']}", None),
    ("PATCH  bravo's finding", "PATCH", f"/api/findings/{finding['bravo']}", {"status": "false_positive"}),
    ("DELETE bravo's finding", "DELETE", f"/api/findings/{finding['bravo']}", None),
]:
    status, _ = call(method, path, token=a, body=body)
    check(f"{label} -> 404", status, 404)

# The cross-tenant asset_id on create is the subtler one: it is the path by
# which a foreign hostname could be echoed back through a finding's
# asset_hostname, and by which a row could be planted in another tenant's view.
status, res = call(
    "POST", "/api/findings", token=a,
    body={"asset_id": asset["bravo"], "title": "planted cross-tenant", "cvss_score": 5.0},
)
check("create finding against bravo's asset -> 404", status, 404)

# Scan scope is a second, independent gate: even in-scope-looking targets that
# belong to another tenant's verified domain must be refused before any packet
# leaves the host.
status, res = call("POST", "/api/scans", token=a, body={"target": domain("bravo")})
check("scan bravo's domain -> 403", status, 403)
check("403 explains why", "verified domains" in str(res.get("detail", "")), True)

print("\n=== list and aggregate endpoints return own rows only ===")
for tag in ("alpha", "bravo"):
    other = "bravo" if tag == "alpha" else "alpha"
    t = tok[tag]

    status, res = call("GET", "/api/assets", token=t)
    check(f"{tag} asset list", [i["hostname"] for i in res.get("items", [])], [f"api.{domain(tag)}"])
    check(f"{tag} asset list total", res.get("total"), 1)

    status, res = call("GET", "/api/findings", token=t)
    check(f"{tag} finding list", [i["title"] for i in res.get("items", [])], [f"{tag} exposure"])

    status, res = call("GET", "/api/findings/stats", token=t)
    check(f"{tag} finding stats total", res.get("total"), 1)

    status, res = call("GET", "/api/assets/stats", token=t)
    check(f"{tag} asset stats total", res.get("total"), 1)

    status, res = call("GET", "/api/scans", token=t)
    check(f"{tag} scan list empty", res.get("total"), 0)

    status, res = call("GET", "/api/reports/dashboard", token=t)
    check(f"{tag} dashboard asset count", res.get("assets_total"), 1)
    check(f"{tag} dashboard open findings", res.get("findings_open"), 1)

    status, res = call("GET", "/api/assets/graph", token=t)
    check(f"{tag} graph excludes {other}", domain(other) in json.dumps(res), False)

    status, res = call("GET", "/api/auth/users", token=t)
    check(f"{tag} user list is own org only", [u["email"] for u in res], [f"owner@{domain(tag)}"])

# Filters and search must not become a bypass: a hostname substring that only
# matches the other tenant's asset should return nothing rather than leak it.
status, res = call("GET", f"/api/assets?hostname=api.{domain('bravo')}", token=a)
check("hostname filter for bravo's asset returns nothing", res.get("total"), 0)
status, res = call("GET", f"/api/assets?hostname=api.{domain('alpha')}", token=a)
check("hostname filter does match own asset", res.get("total"), 1)
status, res = call("GET", "/api/findings?cve_id=CVE-2024-6387", token=a)
check("CVE filter stays org-scoped", [i["title"] for i in res.get("items", [])], ["alpha exposure"])

print("\n=== role gate ===")
status, res = call(
    "POST", "/api/auth/users", token=a,
    body={"email": f"viewer@{domain('alpha')}", "password": PW, "role": "viewer", "full_name": "Read Only"},
)
check("owner can invite a viewer", status, 201)
if status == 201:
    s, r = call("POST", "/api/auth/login", body={"email": f"viewer@{domain('alpha')}", "password": PW})
    check("viewer can log in", s, 200)
    v = r.get("access_token")
    status, _ = call("GET", "/api/assets", token=v)
    check("viewer GET assets -> 200", status, 200)
    status, _ = call("POST", "/api/assets", token=v, body={"hostname": f"new.{domain('alpha')}"})
    check("viewer POST assets -> 403", status, 403)
    status, _ = call("POST", "/api/scans", token=v, body={"target": domain("alpha")})
    check("viewer POST scans -> 403", status, 403)
    status, _ = call("POST", "/api/auth/users", token=v, body={"email": f"x@{domain('alpha')}", "password": PW})
    check("viewer cannot invite -> 403", status, 403)
    status, _ = call("GET", f"/api/assets/{asset['bravo']}", token=v)
    check("viewer still cannot see bravo -> 404", status, 404)

print("\n=== validation and error shape ===")
status, res = call("POST", "/api/assets", token=a, body={"hostname": ""})
check("empty hostname -> 422", status, 422)
status, res = call("POST", "/api/assets", token=a, body={"hostname": f"dup.{domain('alpha')}"})
first = status
status, res = call("POST", "/api/assets", token=a, body={"hostname": f"dup.{domain('alpha')}"})
check("duplicate hostname is handled, not a 500", (first, status), (201, 409))
status, res = call("POST", "/api/auth/register", body={"org_name": "Weak", "domain": "weak.example", "email": f"w@{domain('alpha')}", "password": "alllettersnodigits"})
check("password without a digit -> 422", status, 422)
check("422 names the rule", "digit" in json.dumps(res), True)
status, res = call("GET", f"/api/assets/{uuid.uuid4()}", token=a)
check("unknown uuid -> 404", status, 404)
status, res = call("GET", "/api/assets/not-a-uuid", token=a)
check("malformed uuid -> 422", status, 422)
status, res = call("POST", "/api/auth/register", body={"org_name": "Dup", "domain": domain("alpha"), "email": f"owner@{domain('alpha')}", "password": PW})
check("duplicate email -> 409", status, 409)
check("409 is vague (no account enumeration)", res.get("detail"), "Unable to register with those details")
status, res = call("GET", "/api/assets?limit=99999", token=a)
check("oversized limit -> 422", status, 422)

print("\n=== broker dispatch ===")
# Two outcomes are correct here depending on whether Celery's broker is
# reachable, and both are asserted rather than merely printed. The 503 branch is
# the one this environment exercises (no Redis): the point is that a broker
# outage must not strand a queued scan that no worker will ever pick up.
status, res = call("POST", "/api/scans", token=a, body={"target": domain("alpha")})
if status == 503:
    print("  INFO  broker is down — checking the failure path")
    check("scan dispatch failure -> 503 not 500", status, 503)
    check("503 is actionable", "try again" in str(res.get("detail", "")).lower(), True)
    s, lst = call("GET", "/api/scans", token=a)
    states = [i["status"] for i in lst.get("items", [])]
    check("no scan left stranded in queued", [x for x in states if x == "queued"], [])
    check("the scan is recorded as failed", states, ["failed"])
    errs = [i.get("error") or "" for i in lst.get("items", [])]
    check("failure reason is recorded", all("Could not queue" in e for e in errs), True)
    check("broker host is not leaked to the tenant", any("6379" in e for e in errs), False)

    status, res = call("POST", "/api/reports", token=a, body={"format": "pdf"})
    check("report dispatch failure -> 503 not 500", status, 503)
    s, lst = call("GET", "/api/reports", token=a)
    rstates = [i["status"] for i in lst.get("items", [])]
    check("no report left stranded in pending", [x for x in rstates if x == "pending"], [])
else:
    check("scan queued -> 202", status, 202)
    check("scan starts queued", res.get("status"), "queued")
    # celery_task_id is intentionally absent from ScanOut — internal plumbing.
    check("internal task id is not exposed", "celery_task_id" in res, False)

print(f"\n{'=' * 52}\n  {ok} passed, {fail} failed\n{'=' * 52}")
sys.exit(1 if fail else 0)
