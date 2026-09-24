"""The console's wire types match what the API actually sends.

``frontend/src/lib/types.ts`` opens with an instruction: "These mirror
backend/schemas/*.py field for field. When the API changes, change these — do
not paper over a mismatch in a component, or the drift turns into a runtime
``undefined`` somewhere far from the cause."

Nothing enforced that until this module. The failure it guards against is quiet
in both directions:

* a field the API sends and the interface omits is invisible — the component
  simply never sees data that is sitting in the response;
* a field the interface declares and the API does not send is worse, because
  TypeScript will happily let a component read it and render ``undefined``.
  Its ``string | null`` type even makes the bug look handled.

The check is mechanical: parse the field names out of the TypeScript interface,
call the real endpoint, and compare against the JSON keys that come back. It is
deliberately not a schema-to-schema comparison — the point is to pin the
*serialised* shape, which is what the browser receives.

Scope is intentional rather than exhaustive. These are the two interfaces this
console gained alongside the endpoints they describe; adding a third is a few
lines, and the empty-state assertion below fails loudly if this ever stops
testing anything.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]
TYPES_TS = BACKEND.parent / "frontend" / "src" / "lib" / "types.ts"

DOMAINS = "/api/auth/organisation/domains"
SCHEDULES = "/api/schedules"
PASSWORD = "correct-horse-battery-staple-7"


# --- reading the TypeScript -------------------------------------------------


def _interface_body(source: str, name: str) -> str:
    """The text between the braces of ``export interface <name> { ... }``.

    Brace-counted rather than regex-matched, so a field whose type contains
    braces or a generic cannot end the body early.
    """
    opening = re.search(rf"^export interface {re.escape(name)}\b[^{{]*\{{", source, re.MULTILINE)
    assert opening, f"no `export interface {name}` in types.ts — was it renamed?"

    depth = 1
    index = opening.end()
    while index < len(source) and depth > 0:
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        index += 1

    assert depth == 0, f"unbalanced braces in interface {name}"
    return source[opening.end() : index - 1]


def _interface_fields(source: str, name: str) -> set[str]:
    """Top-level field names of an interface.

    Only lines indented by exactly two spaces are fields; the body's JSDoc
    continuation lines also sit at two spaces, so they are dropped explicitly.
    A nested object literal's keys are indented further and are not fields of
    the interface.
    """
    fields: set[str] = set()
    for line in _interface_body(source, name).splitlines():
        if line.lstrip().startswith(("*", "/*", "//")):
            continue
        match = re.match(r"\s{2}([A-Za-z_][A-Za-z0-9_]*)\??\s*:", line)
        if match:
            fields.add(match.group(1))
    return fields


@pytest.fixture(scope="module")
def types_source() -> str:
    assert TYPES_TS.exists(), f"{TYPES_TS} is missing — the frontend has moved"
    return TYPES_TS.read_text()


# --- helpers ----------------------------------------------------------------


async def _register(client, slug: str, domain: str) -> dict:
    resp = await client.post(
        "/api/auth/register",
        json={
            "org_name": f"{slug} corp",
            "domain": domain,
            "email": f"owner@{domain}",
            "password": PASSWORD,
        },
    )
    assert resp.status_code == 201, resp.text
    return {"headers": {"Authorization": f"Bearer {resp.json()['access_token']}"}}


@pytest.fixture
async def org(client) -> dict:
    return await _register(client, "contract", "contract-corp.example")


def _diff(declared: set[str], sent: set[str], interface: str, endpoint: str) -> str:
    """A message naming both directions, because they have different causes."""
    problems = []
    if sent - declared:
        problems.append(
            f"the API sends {sorted(sent - declared)}, which {interface} does not declare — "
            f"a component cannot see those fields"
        )
    if declared - sent:
        problems.append(
            f"{interface} declares {sorted(declared - sent)}, which {endpoint} does not send — "
            f"TypeScript will let a component read these and render undefined"
        )
    return "; ".join(problems)


# --- domain claims ----------------------------------------------------------


async def test_the_domain_claim_shape_matches_the_console(client, org, types_source):
    """Every field of one claim, pending — the state that carries the DNS challenge."""
    created = await client.post(DOMAINS, json={"domain": "claims.example"}, headers=org["headers"])
    # 200, not 201: routes.domains.add_domain does not pin a created status, and
    # re-adding an existing domain deliberately returns the original claim rather
    # than a new resource. The frontend goes through the same client for both,
    # so it must not depend on the distinction.
    assert created.status_code == 200, created.text
    claim = created.json()

    # The same shape comes back nested inside a verify result, and again as list
    # items — all three go to one renderer in the console, so all three are
    # checked against the one interface.
    listed = await client.get(DOMAINS, headers=org["headers"])
    assert listed.status_code == 200, listed.text
    assert set(listed.json()["items"][0]) == set(claim)

    declared = _interface_fields(types_source, "DomainClaim")
    assert declared, "parsed no fields out of DomainClaim — the parser has rotted"
    assert not _diff(declared, set(claim), "DomainClaim", DOMAINS), _diff(
        declared, set(claim), "DomainClaim", DOMAINS
    )


async def test_the_domain_list_shape_matches_the_console(client, org, types_source):
    """The envelope, and the cap the UI shows as "3 of 25" instead of hardcoding."""
    listed = await client.get(DOMAINS, headers=org["headers"])
    assert listed.status_code == 200, listed.text

    declared = _interface_fields(types_source, "DomainClaimList")
    assert declared == {"items", "limit"}, declared
    assert set(listed.json()) == declared, _diff(declared, set(listed.json()), "DomainClaimList", DOMAINS)


async def test_the_domain_verify_shape_matches_the_console(client, org, types_source):
    """A failed check — the branch that carries the server's own explanation.

    Verification is exercised against a domain with no TXT record, so ``detail``
    is populated. A passing check omits it, and the interface declares it
    nullable for exactly that reason.
    """
    created = await client.post(DOMAINS, json={"domain": "unverifiable.example"}, headers=org["headers"])
    claim_id = created.json()["id"]

    checked = await client.post(f"{DOMAINS}/{claim_id}/verify", headers=org["headers"])
    assert checked.status_code == 200, checked.text
    body = checked.json()
    assert body["verified"] is False, body
    assert body["detail"], "a failed check must explain itself"

    declared = _interface_fields(types_source, "DomainVerifyResult")
    assert not _diff(declared, set(body), "DomainVerifyResult", f"{DOMAINS}/{{id}}/verify"), _diff(
        declared, set(body), "DomainVerifyResult", f"{DOMAINS}/{{id}}/verify"
    )

    # The nested claim is the same shape as the top-level one, so a component
    # can hand `verification` straight to the same renderer.
    assert set(body["verification"]) == _interface_fields(types_source, "DomainClaim")


# --- schedules --------------------------------------------------------------


async def test_the_schedule_shape_matches_the_console(client, org, types_source):
    created = await client.post(
        SCHEDULES,
        json={"name": "nightly", "target": "contract-corp.example", "cadence": "daily"},
        headers=org["headers"],
    )
    assert created.status_code == 201, created.text
    schedule = created.json()

    declared = _interface_fields(types_source, "Schedule")
    assert declared, "parsed no fields out of Schedule — the parser has rotted"
    assert not _diff(declared, set(schedule), "Schedule", SCHEDULES), _diff(
        declared, set(schedule), "Schedule", SCHEDULES
    )


async def test_the_schedule_list_shape_matches_the_console(client, org, types_source):
    listed = await client.get(SCHEDULES, headers=org["headers"])
    assert listed.status_code == 200, listed.text

    declared = _interface_fields(types_source, "ScheduleList")
    assert declared == {"items"}, declared


# --- the enums --------------------------------------------------------------


def test_the_cadences_the_console_offers_are_the_ones_the_api_accepts(types_source):
    """A cadence in the dropdown that the enum does not have is a 422 nobody
    can explain, because the option looks like every other option."""
    from models.base import ScanCadence

    match = re.search(
        r"export const SCAN_CADENCES = \[(.*?)\] as const;", types_source, re.DOTALL
    )
    assert match, "SCAN_CADENCES not found in types.ts"
    declared = set(re.findall(r'"([a-z]+)"', match.group(1)))

    actual = {cadence.value for cadence in ScanCadence}
    assert declared == actual, (
        f"types.ts offers {sorted(declared)}, the backend accepts {sorted(actual)}"
    )


def test_the_domain_statuses_the_console_renders_are_the_ones_the_api_sends(types_source):
    """`DOMAIN_STATUS_LABEL` is a Record over the status union, so a status the
    backend adds without the frontend knowing is a missing badge rather than a
    caught error — the map lookup returns undefined and the badge renders empty."""
    from models.base import DomainVerificationStatus

    match = re.search(
        r"export const DOMAIN_VERIFICATION_STATUSES = \[(.*?)\] as const;", types_source, re.DOTALL
    )
    assert match, "DOMAIN_VERIFICATION_STATUSES not found in types.ts"
    declared = set(re.findall(r'"([a-z_]+)"', match.group(1)))

    actual = {status.value for status in DomainVerificationStatus}
    assert declared == actual, (
        f"types.ts renders {sorted(declared)}, the backend sends {sorted(actual)}"
    )
