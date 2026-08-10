"""Broker-outage behaviour for the two endpoints that enqueue Celery work.

Both ``POST /api/scans`` and ``POST /api/reports`` commit their row *before*
handing the job to Celery, because a task that reaches a worker before its row
exists is a race we would lose. The consequence is that a broker failure leaves
a committed row behind, and it has to be reconciled explicitly.

Getting this wrong is not cosmetic. A stranded scan sits in ``queued`` forever:
it counts against the tenant's five-scan concurrency limit, and the console
shows a scan that no worker will ever pick up. A stranded report is worse for
the UI — the reports page polls for as long as anything is ``pending``, so it
refreshes indefinitely against a job that was never queued.

These tests simulate the outage by making the dispatch call raise, which is what
kombu does when Redis is unreachable (``OperationalError: Error 111 ...``).
"""

from __future__ import annotations

import pytest

from kombu.exceptions import OperationalError


pytestmark = pytest.mark.asyncio


@pytest.fixture
async def org(client) -> dict:
    """An organisation with a verified domain, so targets pass the scope gate."""
    domain = "broker-test.example"
    resp = await client.post(
        "/api/auth/register",
        json={
            "org_name": "broker test",
            "domain": domain,
            "email": f"owner@{domain}",
            "password": "correct-horse-battery-staple-7",
        },
    )
    assert resp.status_code in (200, 201), resp.text
    return {
        "headers": {"Authorization": f"Bearer {resp.json()['access_token']}"},
        "domain": domain,
    }


def _boom(*args, **kwargs):
    """Fail the way kombu does when Redis is unreachable."""
    raise OperationalError("Error 111 connecting to localhost:6379. Connection refused.")


def _break_scan_dispatch(monkeypatch) -> None:
    # dispatch_scan is a plain function, so it is replaced wholesale. The route
    # imports it inside the handler, so the patched attribute is what it gets.
    monkeypatch.setattr("workers.orchestrator.dispatch_scan", _boom)


def _break_report_dispatch(monkeypatch) -> None:
    # build_report is a Celery task object and the route calls .delay() on it.
    # Replacing the task itself would raise AttributeError instead of the
    # broker error, which would test the wrong failure.
    from workers.report_builder import build_report

    monkeypatch.setattr(build_report, "delay", _boom)


async def test_scan_dispatch_failure_does_not_strand_the_scan(client, org, monkeypatch):
    _break_scan_dispatch(monkeypatch)

    resp = await client.post(
        "/api/scans", headers=org["headers"], json={"target": org["domain"]}
    )

    # 503, not 500: the request failed for a reason the caller can act on, and
    # retrying later is the correct response.
    assert resp.status_code == 503, resp.text
    assert "try again" in resp.json()["detail"].lower()

    listing = await client.get("/api/scans", headers=org["headers"])
    items = listing.json()["items"]
    assert len(items) == 1
    scan = items[0]

    # The row is reconciled rather than left mid-flight. Were this still
    # "queued", it would occupy one of five concurrency slots permanently.
    assert scan["status"] == "failed"
    assert scan["completed_at"] is not None
    assert "Could not queue" in (scan["error"] or "")

    # The kombu message names the broker host and port. That is infrastructure
    # detail about our deployment, and this field is rendered in the tenant's
    # console — it belongs in the server log, not the API response.
    assert "6379" not in scan["error"]
    assert "localhost" not in scan["error"]


async def test_failed_dispatch_does_not_consume_the_concurrency_limit(
    client, org, monkeypatch
):
    """Five failed dispatches must not lock the tenant out of scanning.

    MAX_CONCURRENT_SCANS_PER_ORG counts rows in queued/running. If a broker
    outage left them queued, the sixth attempt would 429 — a transient Redis
    blip would permanently disable scanning for that org.
    """
    _break_scan_dispatch(monkeypatch)

    for _ in range(5):
        resp = await client.post(
            "/api/scans", headers=org["headers"], json={"target": org["domain"]}
        )
        assert resp.status_code == 503

    # Broker is back.
    monkeypatch.undo()
    resp = await client.post(
        "/api/scans", headers=org["headers"], json={"target": org["domain"]}
    )
    assert resp.status_code != 429, "failed scans are still counting against the limit"
    assert resp.status_code in (200, 201, 202), resp.text


async def test_report_dispatch_failure_does_not_strand_the_report(
    client, org, monkeypatch
):
    _break_report_dispatch(monkeypatch)

    resp = await client.post("/api/reports", headers=org["headers"], json={"format": "pdf"})
    assert resp.status_code == 503, resp.text

    listing = await client.get("/api/reports", headers=org["headers"])
    items = listing.json()["items"]
    assert len(items) == 1

    # Not "pending" — the reports page polls while anything is pending, so a
    # stranded row turns into an infinite refresh loop in the browser.
    assert items[0]["status"] == "failed"
    assert items[0]["summary"].get("error")
