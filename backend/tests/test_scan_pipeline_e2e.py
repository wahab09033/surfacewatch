"""End-to-end: queue a scan through the API and let the pipeline run.

Everything from ``POST /api/scans`` to the scan row reaching a terminal state,
driven through the real HTTP layer with tasks executing inline. This is the path
that three separate bugs hid in — each one made the request *look* successful
while the scan never progressed — so it is worth exercising as a whole rather
than only in per-module pieces.

The scan target is a domain that does not resolve, which is the point: the
pipeline must complete cleanly on a target with nothing behind it. Real probing
against a live socket is covered in test_workers.py.
"""

from __future__ import annotations

import threading
import uuid

import pytest
from starlette.testclient import TestClient

from db.database import session_scope
from models import Scan, ScanLog, ScanStatus


@pytest.fixture
def app_client(_clean_tables):
    from main import app

    with TestClient(app) as tc:
        yield tc


@pytest.fixture
def propagating_celery():
    """Make eager tasks re-raise, so a broken stage fails the test loudly.

    The suite default swallows task errors (matching production, where a failed
    stage is recorded on the scan row rather than crashing the request). Here we
    want the traceback.
    """
    from workers.celery_app import celery_app

    previous = celery_app.conf.task_eager_propagates
    celery_app.conf.task_eager_propagates = True
    try:
        yield
    finally:
        celery_app.conf.task_eager_propagates = previous


def _register(tc: TestClient) -> dict[str, str]:
    resp = tc.post(
        "/api/auth/register",
        json={
            "org_name": "pipeline corp",
            "domain": "pipeline-e2e.example",
            "email": "owner@pipeline-e2e.example",
            "password": "correct-horse-battery-staple-7",
        },
    )
    assert resp.status_code in (200, 201), resp.text
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def _queue_scan(tc: TestClient, headers: dict[str, str], **config) -> dict:
    resp = tc.post(
        "/api/scans",
        headers=headers,
        json={
            "target": "pipeline-e2e.example",
            "config": {"modules": ["port_scanner"], "passive_only": True, **config},
        },
    )
    assert resp.status_code in (200, 201, 202), resp.text
    return resp.json()


# --- the whole path --------------------------------------------------------


def test_queued_scan_runs_to_completion(app_client, _fake_redis, propagating_celery):
    """POST /api/scans must actually execute the pipeline, not just enqueue it."""
    headers = _register(app_client)
    body = _queue_scan(app_client, headers)
    scan_id = uuid.UUID(body["id"])

    with session_scope() as session:
        row = session.get(Scan, scan_id)
        assert row.status is ScanStatus.COMPLETED, f"scan ended {row.status} ({row.error})"
        assert row.progress == 100
        assert row.started_at is not None
        assert row.completed_at is not None
        assert row.error is None
        # finalise_scan clears the stage when it closes the scan out.
        assert row.current_stage is None
        # The task handle is recorded for operator correlation. It is kept off
        # ScanOut on purpose — clients correlate by scan id, not by broker id.
        assert row.celery_task_id


def test_pipeline_writes_a_durable_log_trail(app_client, _fake_redis, propagating_celery):
    """The stages the orchestrator announced must appear in scan_logs."""
    headers = _register(app_client)
    scan_id = uuid.UUID(_queue_scan(app_client, headers)["id"])

    with session_scope() as session:
        messages = [
            row.message
            for row in session.query(ScanLog)
            .filter(ScanLog.scan_id == scan_id)
            .order_by(ScanLog.timestamp)
        ]

    assert any("Scan started" in m for m in messages)
    assert any("Pipeline:" in m for m in messages)
    assert any("Scan completed" in m for m in messages), messages


def test_logs_are_readable_through_the_api(app_client, _fake_redis, propagating_celery):
    """Whatever the workers wrote must be retrievable by the owning tenant."""
    headers = _register(app_client)
    scan_id = _queue_scan(app_client, headers)["id"]

    resp = app_client.get(f"/api/scans/{scan_id}/logs", headers=headers)
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    items = payload["items"] if isinstance(payload, dict) else payload
    assert items, "pipeline ran but no logs surfaced through the API"

    detail = app_client.get(f"/api/scans/{scan_id}", headers=headers)
    assert detail.status_code == 200
    assert detail.json()["status"] == "completed"


def test_completed_scan_appears_on_the_dashboard(app_client, _fake_redis, propagating_celery):
    headers = _register(app_client)
    _queue_scan(app_client, headers)

    resp = app_client.get("/api/reports/dashboard", headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["scans_last_7d"] >= 1


def test_custom_port_profile_is_honoured(app_client, _fake_redis, propagating_celery):
    """`ports` only applies with port_profile='custom'; prove it reaches the stage."""
    headers = _register(app_client)
    scan_id = uuid.UUID(
        _queue_scan(
            app_client,
            headers,
            passive_only=False,
            port_profile="custom",
            ports=[8080],
        )["id"]
    )

    with session_scope() as session:
        messages = [
            row.message
            for row in session.query(ScanLog).filter(ScanLog.scan_id == scan_id)
        ]

    assert any("Scanning 1 ports" in m for m in messages), messages


# --- regressions -----------------------------------------------------------


def test_dispatch_works_from_a_non_main_thread(_clean_tables):
    """@shared_task resolves through the thread-local current_app.

    Only the thread that constructed the Celery app has current_app set; every
    other thread falls back to Celery's blank "default" app, whose broker is
    amqp://localhost. Without celery_app.set_default() a scan dispatched from a
    worker thread — which is where Starlette runs sync endpoints — would publish
    into a broker that does not exist. Guards that call.
    """
    from workers.orchestrator import run_pipeline

    seen: dict[str, object] = {}

    def _resolve():
        seen["app"] = run_pipeline.app.main
        seen["broker"] = run_pipeline.app.conf.broker_url

    thread = threading.Thread(target=_resolve)
    thread.start()
    thread.join()

    assert seen["app"] == "surfacewatch"
    assert seen["broker"] is not None


def test_every_pipeline_task_is_registered(_clean_tables):
    """The chain is built from task names, which must resolve in this process.

    celery_app.include only imports the stage modules at worker boot. A name
    that is not in the registry raises NotRegistered *after* the scan row is
    already RUNNING, leaving it stuck with no visible error.
    """
    from workers.celery_app import celery_app
    from workers.orchestrator import _TASK_NAMES, _ensure_modules_registered

    _ensure_modules_registered()
    missing = [name for name in _TASK_NAMES.values() if name not in celery_app.tasks]
    assert not missing, f"unregistered pipeline tasks: {missing}"


def test_stages_survive_being_called_inside_a_running_loop(_clean_tables):
    """run_async must not blow up when a loop is already running.

    The stages are sync task bodies that drive asyncio internals. asyncio.run
    refuses to nest, so under task_always_eager — a supported local-dev setting
    — every network stage would die with "cannot be called from a running event
    loop".
    """
    import asyncio

    from workers.context import run_async

    async def _inner() -> str:
        await asyncio.sleep(0)
        return "ok"

    # No loop running: the plain path.
    assert run_async(_inner()) == "ok"

    # Loop running: must still work rather than raise.
    async def _outer() -> str:
        return run_async(_inner())

    assert asyncio.run(_outer()) == "ok"
