"""Step 4 feature tests: AI remediation, Slack alerts, blast radius graph.

These three features share one property that makes them worth testing carefully
rather than smoke-testing: each one hands data to something outside the process.
Remediation sends a host's fingerprint to the Anthropic API, Slack alerting
sends finding titles to a URL an org admin supplied, and the graph endpoint
assembles a whole estate into one response. The failure modes that matter are
therefore about what leaks and what is claimed, not about happy-path shape:

* a stored webhook must not be usable to reach an internal address (SSRF),
* the webhook secret must never appear in a hint, a log, or an API response,
* remediation provenance must not credit a model for text a human rewrote,
* the graph must not put another tenant's hosts in your response.

No test here contacts the network. The Claude call and the Slack POST are both
driven through httpx.MockTransport, which is the real client code path with a
fake socket underneath — a monkeypatched `post` would not exercise the status
handling that most of these assertions are about.
"""

from __future__ import annotations

import json
import uuid

import httpx
import pytest

from services import ai_remediation as ai
from workers import notifier

# pytest.ini sets asyncio_mode = auto, so the async tests below need no marker.
# A module-level one would be wrong here anyway: most of this file is sync.


# --- helpers ----------------------------------------------------------------


def _asset_context(**overrides) -> ai.AssetContext:
    base = {
        "hostname": "web.step4.example",
        "ip": "203.0.113.10",
        "open_ports": [
            {"port": 443, "protocol": "tcp", "service": "https"},
            {"port": 22, "protocol": "tcp", "service": "ssh", "banner": "SSH-2.0-OpenSSH_9.2"},
        ],
        "tech_stack": [{"name": "nginx", "version": "1.18.0", "confidence": 90}],
    }
    base.update(overrides)
    return ai.AssetContext(**base)


def _mock_client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def _claude_reply(payload: dict, status_code: int = 200) -> httpx.Client:
    """An httpx client that answers the Messages API with `payload` as JSON."""

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "api.anthropic.com"
        return httpx.Response(
            status_code,
            json={"content": [{"type": "text", "text": json.dumps(payload)}]},
        )

    return _mock_client(handler)


async def _register(client, slug: str, domain: str) -> dict:
    body = {
        "org_name": f"{slug} org",
        "domain": domain,
        "email": f"owner@{domain}",
        "password": "correct-horse-battery-7-staple",
        "full_name": f"{slug} owner",
    }
    resp = await client.post("/api/auth/register", json=body)
    assert resp.status_code == 201, resp.text
    token = resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    me = await client.get("/api/auth/me", headers=headers)
    assert me.status_code == 200
    return {"headers": headers, "org_id": me.json()["org_id"], "domain": domain}


# --- Slack: URL validation is a security control ---------------------------


def test_webhook_must_be_https_on_the_slack_host():
    assert notifier.validate_webhook_url(
        "https://hooks.slack.com/services/T01/B02/abcdefghijklmnopqrstuvwx"
    )

    for bad in [
        # The SSRF cases. Cloud metadata is the one that turns a settings field
        # into credential theft, so it is named explicitly.
        "http://169.254.169.254/latest/meta-data/",
        "https://169.254.169.254/services/x/y/z",
        "https://localhost/services/x/y/z",
        "http://hooks.slack.com/services/T01/B02/secret",  # plaintext
        # Suffix trick: an attacker-controlled host that merely *ends with* the
        # Slack domain. Passes a naive `endswith` check, fails an exact match.
        "https://hooks.slack.com.evil.test/services/T01/B02/secret",
        "https://evil.test/hooks.slack.com/services/T01/B02/secret",
        # Right host, wrong endpoint — not an incoming webhook.
        "https://hooks.slack.com/api/chat.postMessage",
        "",
        "   ",
    ]:
        with pytest.raises(notifier.InvalidWebhookURL):
            notifier.validate_webhook_url(bad)


def test_webhook_length_is_bounded():
    long_url = "https://hooks.slack.com/services/T01/B02/" + ("a" * 600)
    with pytest.raises(notifier.InvalidWebhookURL):
        notifier.validate_webhook_url(long_url)


def test_redact_keeps_the_team_and_channel_but_never_the_secret():
    secret = "zzzzSECRETzzzzSECRETzzzz"
    hint = notifier.redact(f"https://hooks.slack.com/services/T0ALPHA/B0BETA/{secret}")

    assert hint is not None
    assert "T0ALPHA" in hint and "B0BETA" in hint
    assert secret not in hint
    assert notifier.redact(None) is None
    assert notifier.redact("") is None


def test_redact_does_not_crash_on_an_unexpected_shape():
    # Defensive: rows written before validation existed could be any shape, and
    # a hint that raises would take out GET /organisation for that org.
    assert notifier.redact("https://hooks.slack.com/") is not None


# --- Slack: message composition --------------------------------------------


def _finding(n: int, severity: str = "critical") -> dict:
    return {
        "title": f"Finding {n}",
        "hostname": f"host{n}.step4.example",
        "cve_id": f"CVE-2024-{1000 + n}",
        "cvss_score": 9.8,
        "severity": severity,
    }


def test_blocks_carry_a_fallback_text_for_the_push_notification():
    payload = notifier.build_blocks(
        findings=[_finding(1)], org_name="Acme", scan_id="scan-1"
    )
    # Without top-level `text`, Slack's mobile push arrives blank.
    assert payload["text"]
    assert "Acme" in payload["text"]
    assert payload["blocks"][0]["type"] == "header"


def test_blocks_cap_the_list_and_say_what_was_left_out():
    payload = notifier.build_blocks(
        findings=[_finding(n) for n in range(25)], org_name="Acme", scan_id=None
    )
    rendered = json.dumps(payload)

    # Slack drops everything past 50 blocks silently; the cap has to be ours.
    assert len(payload["blocks"]) <= 50
    assert "and 15 more" in rendered
    assert "Finding 0" in rendered
    assert "Finding 24" not in rendered


def test_blocks_handle_a_finding_with_no_cvss_or_cve():
    payload = notifier.build_blocks(
        findings=[{"title": "Manual finding", "severity": "critical"}],
        org_name="Acme",
        scan_id=None,
    )
    rendered = json.dumps(payload)
    assert "not scored" in rendered
    assert "unknown" in rendered  # hostname placeholder


def test_singular_and_plural_headings():
    one = notifier.build_blocks(findings=[_finding(1)], org_name="A", scan_id=None)
    two = notifier.build_blocks(findings=[_finding(1), _finding(2)], org_name="A", scan_id=None)
    assert "1 new critical finding —" in one["text"]
    assert "2 new critical findings —" in two["text"]


# --- Slack: delivery -------------------------------------------------------


def test_post_refuses_a_stored_url_that_fails_validation():
    """A row written before validation existed must still not be callable."""
    called = False

    def handler(request):  # pragma: no cover - must never run
        nonlocal called
        called = True
        return httpx.Response(200, text="ok")

    with _mock_client(handler) as client:
        assert notifier.post("http://169.254.169.254/", {"text": "x"}, client=client) is False
    assert called is False


def test_post_reports_failure_on_a_revoked_webhook():
    with _mock_client(lambda r: httpx.Response(404, text="no_service")) as client:
        assert (
            notifier.post(
                "https://hooks.slack.com/services/T01/B02/abcdefghijklmnopqrstuvwx",
                {"text": "x"},
                client=client,
            )
            is False
        )


def test_post_never_raises_on_a_transport_error():
    def handler(request):
        raise httpx.ConnectTimeout("timed out", request=request)

    with _mock_client(handler) as client:
        assert (
            notifier.post(
                "https://hooks.slack.com/services/T01/B02/abcdefghijklmnopqrstuvwx",
                {"text": "x"},
                client=client,
            )
            is False
        )


def test_post_does_not_log_the_webhook_url(caplog):
    """str() on an httpx error embeds the URL, which is the credential."""
    secret = "zzzzSECRETzzzzSECRETzzzz"
    url = f"https://hooks.slack.com/services/T01/B02/{secret}"

    def handler(request):
        raise httpx.ConnectError("boom", request=request)

    with caplog.at_level("DEBUG"), _mock_client(handler) as client:
        notifier.post(url, {"text": "x"}, client=client)

    assert secret not in caplog.text
    assert "hooks.slack.com" not in caplog.text


def test_notify_critical_is_a_no_op_without_a_webhook(org_row):
    result = notifier.notify_critical.run(str(org_row), [_finding(1)], None)
    assert result == {"sent": False, "reason": "not_configured"}


def test_notify_critical_ignores_findings_below_the_threshold(org_row):
    # Checked before the org is even loaded, so a medium finding costs nothing.
    result = notifier.notify_critical.run(str(org_row), [_finding(1, "medium")], None)
    assert result == {"sent": False, "reason": "below_threshold"}


def test_notify_critical_handles_a_deleted_org():
    result = notifier.notify_critical.run(str(uuid.uuid4()), [_finding(1)], None)
    assert result == {"sent": False, "reason": "org_missing"}


def test_notify_critical_can_be_disabled_globally(org_row, monkeypatch):
    from config import settings

    monkeypatch.setattr(settings, "slack_notifications_enabled", False)
    assert notifier.notify_critical.run(str(org_row), [_finding(1)], None) == {
        "sent": False,
        "reason": "disabled",
    }


def test_notify_critical_delivers_when_configured(org_row, monkeypatch):
    from db.database import session_scope
    from models import Organisation

    url = "https://hooks.slack.com/services/T01/B02/abcdefghijklmnopqrstuvwx"
    with session_scope() as session:
        session.get(Organisation, org_row).slack_webhook_url = url

    seen: list[dict] = []

    def fake_post(target, payload, **kwargs):
        seen.append({"url": target, "payload": payload})
        return True

    monkeypatch.setattr(notifier, "post", fake_post)
    result = notifier.notify_critical.run(str(org_row), [_finding(1), _finding(2)], "scan-9")

    assert result == {"sent": True, "count": 2}
    assert seen[0]["url"] == url
    body = json.dumps(seen[0]["payload"])
    # The spec asks for title, asset, CVE and CVSS in the alert.
    assert "Finding 1" in body
    assert "host1.step4.example" in body
    assert "CVE-2024-1001" in body
    assert "9.8" in body
    assert "scan-9" in body


# --- AI remediation: prompt and parsing ------------------------------------


def test_prompt_carries_the_host_specifics_not_just_the_cve():
    """The whole point of the feature: advice for *this* host."""
    prompt = ai.build_prompt(
        cve_id="CVE-2021-23017",
        cvss_score=9.4,
        cvss_vector="CVSS:3.1/AV:N/AC:H",
        severity="critical",
        description="A security issue in nginx resolver.",
        product="nginx",
        version="1.18.0",
        asset=_asset_context(),
    )
    for expected in [
        "CVE-2021-23017",
        "9.4",
        "nginx 1.18.0",
        "web.step4.example",
        "203.0.113.10",
        "443/tcp",
        "22/tcp",
        "SSH-2.0-OpenSSH_9.2",
    ]:
        assert expected in prompt, expected


def test_prompt_truncates_a_huge_nvd_description():
    prompt = ai.build_prompt(
        cve_id="CVE-2024-0001",
        cvss_score=None,
        cvss_vector=None,
        severity="high",
        description="x" * 9_000,
        product="nginx",
        version="1.18.0",
        asset=_asset_context(),
    )
    assert "x" * 2_000 in prompt
    assert "x" * 2_001 not in prompt
    assert "not scored by NVD" in prompt


def test_prompt_is_coherent_for_a_host_with_nothing_fingerprinted():
    prompt = ai.build_prompt(
        cve_id="CVE-2024-0001",
        cvss_score=1.0,
        cvss_vector=None,
        severity="low",
        description=None,
        product="unknown",
        version="unknown",
        asset=_asset_context(open_ports=[], tech_stack=[], ip=None),
    )
    assert "None detected as open." in prompt
    assert "Nothing fingerprinted." in prompt
    assert "not resolved" in prompt


def test_cache_key_ignores_identity_but_tracks_the_stack():
    """Two hosts with the same stack should share one paid-for answer."""
    a = _asset_context(hostname="a.example", ip="198.51.100.1")
    b = _asset_context(hostname="b.example", ip="198.51.100.2")
    assert ai.cache_key("CVE-1", "nginx", "1.18.0", a) == ai.cache_key(
        "CVE-1", "nginx", "1.18.0", b
    )

    patched = _asset_context(tech_stack=[{"name": "nginx", "version": "1.24.0"}])
    assert ai.cache_key("CVE-1", "nginx", "1.18.0", a) != ai.cache_key(
        "CVE-1", "nginx", "1.18.0", patched
    )
    # Port order must not change identity, or the hit rate collapses.
    reordered = _asset_context(open_ports=list(reversed(_asset_context().open_ports)))
    assert a.fingerprint() == reordered.fingerprint()


def test_response_parsing_tolerates_fences_and_preamble():
    payload = {"summary": "Upgrade nginx.", "steps": ["apt upgrade nginx"]}
    for raw in [
        json.dumps(payload),
        f"```json\n{json.dumps(payload)}\n```",
        f"```\n{json.dumps(payload)}\n```",
        f"Here is the remediation:\n{json.dumps(payload)}\nHope that helps.",
    ]:
        parsed = ai._parse_response(raw)
        assert parsed is not None, raw
        assert parsed["summary"] == "Upgrade nginx."

    for bad in ["not json at all", "", "[1, 2, 3]", "{unclosed"]:
        assert ai._parse_response(bad) is None


def test_rendered_markdown_surfaces_what_the_model_could_not_determine():
    text = ai._render(
        {
            "summary": "Upgrade nginx to 1.20.1.",
            "steps": ["apt-get install nginx=1.20.1", "systemctl reload nginx"],
            "mitigation": "Disable the resolver directive.",
            "exposure_note": "443 is internet-facing.",
            "uncertain": ["Whether the distro backported the fix."],
        }
    )
    assert "Upgrade nginx to 1.20.1." in text
    assert "1. apt-get install nginx=1.20.1" in text
    assert "2. systemctl reload nginx" in text
    assert "If you cannot patch today:" in text
    assert "Exposure on this host:" in text
    # The honesty clause: never silently drop this.
    assert "Not determined from scan data:" in text
    assert "Whether the distro backported the fix." in text


def test_render_drops_null_strings_the_model_sometimes_emits():
    text = ai._render(
        {"summary": "Patch it.", "steps": [], "mitigation": "none", "exposure_note": "null"}
    )
    assert text == "Patch it."


# --- AI remediation: generate() and its fallbacks -------------------------


def _enable_ai(monkeypatch):
    from config import settings

    monkeypatch.setattr(settings, "ai_remediation_enabled", True)
    monkeypatch.setattr(settings, "ai_remediation_api_key", "sk-ant-test-key")


def _generate(fallback="Standard advice: upgrade the package.", **kwargs):
    defaults = {
        "cve_id": "CVE-2021-23017",
        "cvss_score": 9.4,
        "cvss_vector": None,
        "severity": "critical",
        "description": "nginx resolver issue",
        "product": "nginx",
        "version": "1.18.0",
        "asset": _asset_context(),
        "fallback": fallback,
    }
    defaults.update(kwargs)
    return ai.generate(**defaults)


def test_generate_returns_template_when_no_api_key_is_set(monkeypatch):
    from config import settings

    monkeypatch.setattr(settings, "ai_remediation_api_key", "")
    result = _generate()
    assert result.source == ai.SOURCE_TEMPLATE
    assert result.is_ai is False
    assert result.text == "Standard advice: upgrade the package."


def test_generate_records_model_and_confidence_on_success(monkeypatch):
    _enable_ai(monkeypatch)
    with _claude_reply(
        {
            "summary": "Upgrade nginx to 1.20.1 on this host.",
            "steps": ["apt-get install nginx=1.20.1"],
            "confidence": "medium",
            "uncertain": ["Whether Debian backported the patch."],
        }
    ) as client:
        result = _generate(http_client=client)

    assert result.source == ai.SOURCE_AI
    assert result.is_ai is True
    assert result.model  # provenance the UI renders
    assert result.confidence == "medium"
    assert result.uncertain == ["Whether Debian backported the patch."]
    assert "1.20.1" in result.text


@pytest.mark.parametrize("status_code", [401, 429, 500, 400])
def test_every_api_failure_falls_back_to_the_template(monkeypatch, status_code):
    _enable_ai(monkeypatch)
    with _mock_client(lambda r: httpx.Response(status_code, json={"error": "x"})) as client:
        result = _generate(http_client=client)
    assert result.source == ai.SOURCE_TEMPLATE
    assert result.text == "Standard advice: upgrade the package."


def test_a_transport_error_falls_back_rather_than_raising(monkeypatch):
    _enable_ai(monkeypatch)

    def handler(request):
        raise httpx.ReadTimeout("slow", request=request)

    with _mock_client(handler) as client:
        result = _generate(http_client=client)
    assert result.source == ai.SOURCE_TEMPLATE


def test_well_formed_but_empty_advice_falls_back(monkeypatch):
    """An empty remediation field is worse than the generic text."""
    _enable_ai(monkeypatch)
    with _claude_reply({"summary": "", "steps": []}) as client:
        result = _generate(http_client=client)
    assert result.source == ai.SOURCE_TEMPLATE


def test_non_json_prose_falls_back(monkeypatch):
    _enable_ai(monkeypatch)

    def handler(request):
        return httpx.Response(200, json={"content": [{"type": "text", "text": "Sorry, no."}]})

    with _mock_client(handler) as client:
        result = _generate(http_client=client)
    assert result.source == ai.SOURCE_TEMPLATE


def test_cache_hit_is_marked_as_cached_and_makes_no_api_call(monkeypatch):
    _enable_ai(monkeypatch)

    class Cache:
        def __init__(self, stored):
            self.stored = stored

        def get(self, key):
            return self.stored

        def setex(self, *a, **k):
            pass

    entry = json.dumps(
        {
            "text": "Cached advice.",
            "model": "claude-sonnet-5",
            "confidence": "high",
            "uncertain": [],
        }
    )

    def handler(request):  # pragma: no cover - must never run
        raise AssertionError("cache hit must not call the API")

    with _mock_client(handler) as client:
        result = _generate(http_client=client, redis_client=Cache(entry))

    assert result.source == ai.SOURCE_CACHE
    assert result.is_ai is True
    assert result.text == "Cached advice."


def test_a_poisoned_cache_entry_regenerates(monkeypatch):
    _enable_ai(monkeypatch)

    class Cache:
        def get(self, key):
            return "{not json"

        def setex(self, *a, **k):
            self.written = True

    with _claude_reply({"summary": "Fresh advice.", "steps": ["step"]}) as client:
        result = _generate(http_client=client, redis_client=Cache())

    assert result.source == ai.SOURCE_AI
    assert "Fresh advice." in result.text


def test_a_redis_outage_does_not_break_generation(monkeypatch):
    _enable_ai(monkeypatch)

    class Broken:
        def get(self, key):
            raise RuntimeError("redis is down")

        def setex(self, *a, **k):
            raise RuntimeError("redis is down")

    with _claude_reply({"summary": "Still works.", "steps": ["step"]}) as client:
        result = _generate(http_client=client, redis_client=Broken())

    assert result.source == ai.SOURCE_AI


def test_the_api_key_is_sent_as_a_header_and_not_in_the_body(monkeypatch):
    _enable_ai(monkeypatch)
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(request.headers)
        captured["body"] = request.content.decode()
        return httpx.Response(
            200, json={"content": [{"type": "text", "text": '{"summary":"ok","steps":["s"]}'}]}
        )

    with _mock_client(handler) as client:
        _generate(http_client=client)

    assert captured["headers"]["x-api-key"] == "sk-ant-test-key"
    assert captured["headers"]["anthropic-version"] == ai.ANTHROPIC_VERSION
    assert "sk-ant-test-key" not in captured["body"]


# --- provenance: an analyst's edit must not be credited to the model -------


async def test_editing_remediation_re_attributes_it_to_the_analyst(client):
    org = await _register(client, "prov", "prov-corp.example")

    asset = await client.post(
        "/api/assets",
        json={"hostname": "web.prov-corp.example", "ip": "203.0.113.20"},
        headers=org["headers"],
    )
    assert asset.status_code == 201, asset.text

    created = await client.post(
        "/api/findings",
        json={
            "asset_id": asset.json()["id"],
            "title": "nginx 1.18.0 affected by CVE-2021-23017",
            "cve_id": "CVE-2021-23017",
            "cvss_score": 9.4,
            "severity": "critical",
            "remediation": "AI-written advice for this host.",
        },
        headers=org["headers"],
    )
    assert created.status_code == 201, created.text
    finding_id = created.json()["id"]

    # Stamp AI provenance directly: the worker path needs a live scan, and what
    # is under test is the PATCH route's handling of it.
    from db.database import session_scope
    from models import Finding

    with session_scope() as session:
        row = session.get(Finding, uuid.UUID(finding_id))
        row.evidence = {
            "remediation_source": ai.SOURCE_AI,
            "remediation_model": "claude-sonnet-5",
            "remediation_confidence": "medium",
            "remediation_uncertain": ["Whether the distro backported the fix."],
            "cpe": "cpe:2.3:a:nginx:nginx:1.18.0",
        }

    patched = await client.patch(
        f"/api/findings/{finding_id}",
        json={"remediation": "Actually, this host is behind the WAF. Patch next window."},
        headers=org["headers"],
    )
    assert patched.status_code == 200, patched.text
    evidence = patched.json()["evidence"]

    assert evidence["remediation_source"] == "analyst"
    assert evidence["remediation_model"] is None
    assert evidence["remediation_confidence"] is None
    assert evidence["remediation_uncertain"] == []
    # Unrelated evidence keys must survive — this is a shared JSONB blob.
    assert evidence["cpe"] == "cpe:2.3:a:nginx:nginx:1.18.0"


async def test_triaging_without_touching_the_text_keeps_the_ai_provenance(client):
    """Re-saving the form must not silently rewrite history."""
    org = await _register(client, "keep", "keep-corp.example")
    created = await client.post(
        "/api/findings",
        json={
            "title": "A finding",
            "severity": "high",
            "remediation": "  AI advice.  ",
        },
        headers=org["headers"],
    )
    finding_id = created.json()["id"]

    from db.database import session_scope
    from models import Finding

    with session_scope() as session:
        session.get(Finding, uuid.UUID(finding_id)).evidence = {
            "remediation_source": ai.SOURCE_AI,
            "remediation_model": "claude-sonnet-5",
        }

    # Status change only.
    status_only = await client.patch(
        f"/api/findings/{finding_id}",
        json={"status": "triaged"},
        headers=org["headers"],
    )
    assert status_only.json()["evidence"]["remediation_source"] == "claude"

    # Same text, differently whitespaced — the UI trims before sending.
    resent = await client.patch(
        f"/api/findings/{finding_id}",
        json={"remediation": "AI advice.", "notes": "Looks real."},
        headers=org["headers"],
    )
    evidence = resent.json()["evidence"]
    assert evidence["remediation_source"] == "claude"
    assert evidence["analyst_notes"] == "Looks real."


# --- Slack webhook endpoints ----------------------------------------------


async def test_the_api_never_returns_the_stored_webhook(client):
    org = await _register(client, "hook", "hook-corp.example")
    secret = "zzzzSECRETzzzzSECRETzzzz"
    url = f"https://hooks.slack.com/services/T0HOOK/B0HOOK/{secret}"

    saved = await client.put(
        "/api/auth/organisation/slack-webhook",
        json={"webhook_url": url},
        headers=org["headers"],
    )
    assert saved.status_code == 200, saved.text
    body = saved.json()

    assert body["slack_webhook_configured"] is True
    assert secret not in json.dumps(body)
    assert "T0HOOK" in body["slack_webhook_hint"]

    fetched = await client.get("/api/auth/organisation", headers=org["headers"])
    assert secret not in json.dumps(fetched.json())
    assert fetched.json()["slack_webhook_configured"] is True


async def test_the_api_rejects_a_non_slack_webhook(client):
    org = await _register(client, "ssrf", "ssrf-corp.example")
    for bad in [
        "http://169.254.169.254/latest/meta-data/",
        "https://hooks.slack.com.evil.test/services/T/B/C",
        "https://hooks.slack.com/api/chat.postMessage",
    ]:
        resp = await client.put(
            "/api/auth/organisation/slack-webhook",
            json={"webhook_url": bad},
            headers=org["headers"],
        )
        assert resp.status_code == 422, (bad, resp.status_code)

    still_off = await client.get("/api/auth/organisation", headers=org["headers"])
    assert still_off.json()["slack_webhook_configured"] is False


async def test_null_clears_the_integration(client):
    org = await _register(client, "clear", "clear-corp.example")
    await client.put(
        "/api/auth/organisation/slack-webhook",
        json={"webhook_url": "https://hooks.slack.com/services/T01/B02/abcdefghijklmnopqrst"},
        headers=org["headers"],
    )
    cleared = await client.put(
        "/api/auth/organisation/slack-webhook",
        json={"webhook_url": None},
        headers=org["headers"],
    )
    assert cleared.status_code == 200
    assert cleared.json()["slack_webhook_configured"] is False
    assert cleared.json()["slack_webhook_hint"] is None


async def test_a_viewer_cannot_redirect_security_alerts(client):
    """Redirecting the alert channel is a plausible way to hide an intrusion."""
    org = await _register(client, "roles", "roles-corp.example")
    invited = await client.post(
        "/api/auth/users",
        json={
            "email": "viewer@roles-corp.example",
            "password": "correct-horse-battery-7-staple",
            "role": "viewer",
        },
        headers=org["headers"],
    )
    assert invited.status_code == 201, invited.text

    login = await client.post(
        "/api/auth/login",
        json={
            "email": "viewer@roles-corp.example",
            "password": "correct-horse-battery-7-staple",
        },
    )
    viewer = {"Authorization": f"Bearer {login.json()['access_token']}"}

    refused = await client.put(
        "/api/auth/organisation/slack-webhook",
        json={"webhook_url": "https://hooks.slack.com/services/T01/B02/abcdefghijklmnopqrst"},
        headers=viewer,
    )
    assert refused.status_code == 403

    tested = await client.post(
        "/api/auth/organisation/slack-webhook/test", headers=viewer
    )
    assert tested.status_code == 403


async def test_the_test_button_reports_a_missing_integration(client):
    org = await _register(client, "notest", "notest-corp.example")
    resp = await client.post("/api/auth/organisation/slack-webhook/test", headers=org["headers"])
    assert resp.status_code == 400
    assert "No Slack webhook" in resp.json()["detail"]


async def test_the_test_button_surfaces_a_revoked_webhook(client, monkeypatch):
    org = await _register(client, "revoked", "revoked-corp.example")
    await client.put(
        "/api/auth/organisation/slack-webhook",
        json={"webhook_url": "https://hooks.slack.com/services/T01/B02/abcdefghijklmnopqrst"},
        headers=org["headers"],
    )

    # routes/auth.py imports notifier.post inside the handler, so patching the
    # attribute on the module is what the handler will resolve.
    monkeypatch.setattr(notifier, "post", lambda *a, **k: False)
    resp = await client.post("/api/auth/organisation/slack-webhook/test", headers=org["headers"])
    assert resp.status_code == 502
    assert "revoked" in resp.json()["detail"]


async def test_the_test_button_confirms_a_working_webhook(client, monkeypatch):
    org = await _register(client, "works", "works-corp.example")
    await client.put(
        "/api/auth/organisation/slack-webhook",
        json={"webhook_url": "https://hooks.slack.com/services/T01/B02/abcdefghijklmnopqrst"},
        headers=org["headers"],
    )

    sent: list = []

    def fake_post(url, payload, **kwargs):
        sent.append(payload)
        return True

    monkeypatch.setattr(notifier, "post", fake_post)
    resp = await client.post("/api/auth/organisation/slack-webhook/test", headers=org["headers"])
    assert resp.status_code == 200
    # A test message must be recognisable as a test, not mistaken for an alert.
    assert "test" in json.dumps(sent[0]).lower()


# --- blast radius graph ---------------------------------------------------


async def _seed_estate(client, org: dict) -> None:
    """Two hosts on one shared IP plus a third on its own."""
    domain = org["domain"]
    for hostname, ip, ports in [
        ("www." + domain, "203.0.113.30", [{"port": 443, "state": "open", "service": "https"}]),
        ("api." + domain, "203.0.113.30", [{"port": 22, "state": "open", "service": "ssh"}]),
        ("db." + domain, "203.0.113.31", [{"port": 3306, "state": "closed", "service": "mysql"}]),
    ]:
        created = await client.post(
            "/api/assets", json={"hostname": hostname, "ip": ip}, headers=org["headers"]
        )
        assert created.status_code == 201, created.text

        from db.database import session_scope
        from models import Asset

        with session_scope() as session:
            session.get(Asset, uuid.UUID(created.json()["id"])).ports = ports


async def test_graph_is_reachable_and_not_shadowed_by_the_uuid_route(client):
    """FastAPI matches in declaration order; /graph must precede /{asset_id}."""
    org = await _register(client, "graph", "graph-corp.example")
    resp = await client.get("/api/assets/graph", headers=org["headers"])
    assert resp.status_code == 200, resp.text


async def test_graph_connects_domain_to_subdomain_to_ip_to_port(client):
    org = await _register(client, "shape", "shape-corp.example")
    await _seed_estate(client, org)

    resp = await client.get("/api/assets/graph", headers=org["headers"])
    body = resp.json()
    nodes = {n["id"]: n for n in body["nodes"]}
    kinds = {n["kind"] for n in body["nodes"]}

    assert kinds == {"domain", "subdomain", "ip", "port"}
    assert body["total_assets"] == 3
    assert body["truncated"] is False

    # The shared IP is one node, not two, and says how many hosts land on it.
    ips = [n for n in body["nodes"] if n["kind"] == "ip"]
    shared = [n for n in ips if n["shared_by"] == 2]
    assert len(shared) == 1, [(n["label"], n["shared_by"]) for n in ips]
    assert shared[0]["label"] == "203.0.113.30"

    # Closed ports are not exposure and must not appear.
    port_labels = {n["label"] for n in body["nodes"] if n["kind"] == "port"}
    assert "3306" not in port_labels
    assert {"443", "22"} <= port_labels

    # Every link resolves to a node that was actually sent.
    for link in body["links"]:
        assert link["source"] in nodes, link
        assert link["target"] in nodes, link

    # No duplicate edges: d3 treats a repeat as a second spring.
    pairs = [(link["source"], link["target"]) for link in body["links"]]
    assert len(pairs) == len(set(pairs))

    # Subdomain nodes carry the id the AssetDrawer opens with.
    for node in body["nodes"]:
        if node["kind"] == "subdomain":
            assert node["asset_id"]
        else:
            assert node["asset_id"] is None


async def test_ports_can_be_excluded(client):
    org = await _register(client, "noports", "noports-corp.example")
    await _seed_estate(client, org)

    resp = await client.get(
        "/api/assets/graph", params={"include_ports": "false"}, headers=org["headers"]
    )
    assert {n["kind"] for n in resp.json()["nodes"]} == {"domain", "subdomain", "ip"}


async def test_graph_truncation_is_declared_not_silent(client):
    org = await _register(client, "trunc", "trunc-corp.example")
    for n in range(4):
        await client.post(
            "/api/assets",
            json={"hostname": f"h{n}.trunc-corp.example"},
            headers=org["headers"],
        )

    resp = await client.get(
        "/api/assets/graph", params={"max_assets": 2}, headers=org["headers"]
    )
    body = resp.json()
    assert body["total_assets"] == 4
    assert body["truncated"] is True
    assert body["truncated_reason"]
    assert len([n for n in body["nodes"] if n["kind"] == "subdomain"]) == 2


async def test_graph_does_not_leak_another_tenant(client):
    a = await _register(client, "ga", "ga-corp.example")
    b = await _register(client, "gb", "gb-corp.example")
    await _seed_estate(client, a)

    body = (await client.get("/api/assets/graph", headers=b["headers"])).json()
    rendered = json.dumps(body)

    assert body["total_assets"] == 0
    assert "ga-corp.example" not in rendered
    assert "203.0.113.30" not in rendered


async def test_graph_requires_authentication(client):
    assert (await client.get("/api/assets/graph")).status_code in (401, 403)


# --- fixtures -------------------------------------------------------------


@pytest.fixture
def org_row(_clean_tables) -> uuid.UUID:
    """A bare organisation row, for the worker-level tests."""
    from db.database import session_scope
    from models import Organisation

    with session_scope() as session:
        org = Organisation(
            id=uuid.uuid4(),
            name="step4 org",
            domain="step4.example",
            verified_domains=["step4.example"],
        )
        session.add(org)
        session.flush()
        return org.id
