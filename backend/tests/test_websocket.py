"""WebSocket tests for /ws/scan/{scan_id}.

Covers the two things that matter about this endpoint: it must not leak another
tenant's scan, and it must actually deliver log lines published to
``scan:{scan_id}:logs`` — including events that were emitted before the client
connected.

Starlette's TestClient is used rather than httpx's ASGI transport, because the
latter does not speak the WebSocket protocol. It runs the app in its own thread
with its own event loop, so these tests use a sync DB session for setup.
"""

from __future__ import annotations

import uuid

import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

WS_UNAUTHORIZED = 4401
WS_NOT_FOUND = 4404


# --- helpers ----------------------------------------------------------------


@pytest.fixture
def app_client(_clean_tables):
    from main import app

    with TestClient(app) as tc:
        yield tc


def _register(tc: TestClient, slug: str, domain: str) -> dict:
    resp = tc.post(
        "/api/auth/register",
        json={
            "org_name": f"{slug} corp",
            "domain": domain,
            "email": f"owner@{domain}",
            "password": "correct-horse-battery-staple-7",
        },
    )
    assert resp.status_code in (200, 201), resp.text
    token = resp.json()["access_token"]
    me = tc.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200, me.text
    return {"token": token, "org_id": me.json()["org_id"], "domain": domain}


def _make_scan(org_id: str, target: str, status=None) -> uuid.UUID:
    """Insert a scan row directly, bypassing the queueing path."""
    from db.database import session_scope
    from models import Scan, ScanStatus

    with session_scope() as session:
        scan = Scan(
            id=uuid.uuid4(),
            org_id=uuid.UUID(org_id),
            target=target,
            status=status or ScanStatus.RUNNING,
            config={},
        )
        session.add(scan)
        session.flush()
        return scan.id


# --- auth -------------------------------------------------------------------


def test_missing_token_is_rejected(app_client, _fake_redis):
    a = _register(app_client, "alpha", "alpha-ws.example")
    scan_id = _make_scan(a["org_id"], a["domain"])

    with pytest.raises(WebSocketDisconnect) as exc:
        with app_client.websocket_connect(f"/ws/scan/{scan_id}") as ws:
            ws.receive_json()
    assert exc.value.code == WS_UNAUTHORIZED


def test_garbage_token_is_rejected(app_client, _fake_redis):
    a = _register(app_client, "alpha", "alpha-ws.example")
    scan_id = _make_scan(a["org_id"], a["domain"])

    with pytest.raises(WebSocketDisconnect) as exc:
        with app_client.websocket_connect(f"/ws/scan/{scan_id}?token=not-a-jwt") as ws:
            ws.receive_json()
    assert exc.value.code == WS_UNAUTHORIZED


def test_cross_org_scan_is_not_found(app_client, _fake_redis):
    """Tenant B must not be able to attach to tenant A's live scan stream."""
    a = _register(app_client, "alpha", "alpha-ws.example")
    b = _register(app_client, "beta", "beta-ws.example")
    scan_id = _make_scan(a["org_id"], a["domain"])

    with pytest.raises(WebSocketDisconnect) as exc:
        with app_client.websocket_connect(
            f"/ws/scan/{scan_id}?token={b['token']}"
        ) as ws:
            ws.receive_json()
    assert exc.value.code == WS_NOT_FOUND

    # A non-existent id gives the same code, so the two are indistinguishable.
    with pytest.raises(WebSocketDisconnect) as exc2:
        with app_client.websocket_connect(
            f"/ws/scan/{uuid.uuid4()}?token={b['token']}"
        ) as ws:
            ws.receive_json()
    assert exc2.value.code == exc.value.code


# --- streaming --------------------------------------------------------------


def test_owner_receives_snapshot(app_client, _fake_redis):
    a = _register(app_client, "alpha", "alpha-ws.example")
    scan_id = _make_scan(a["org_id"], a["domain"])

    with app_client.websocket_connect(f"/ws/scan/{scan_id}?token={a['token']}") as ws:
        snapshot = ws.receive_json()

    assert snapshot["type"] == "snapshot"
    assert snapshot["scan_id"] == str(scan_id)
    assert snapshot["target"] == a["domain"]
    assert snapshot["status"] == "running"


def test_history_is_replayed_to_a_late_joiner(app_client, _fake_redis):
    """Events published before the client connects must still arrive."""
    from core.events import log_event, publish

    a = _register(app_client, "alpha", "alpha-ws.example")
    scan_id = _make_scan(a["org_id"], a["domain"])

    publish(scan_id, log_event(scan_id, "first line", stage="subdomain_enum"))
    publish(scan_id, log_event(scan_id, "second line", stage="port_scanner"))

    with app_client.websocket_connect(f"/ws/scan/{scan_id}?token={a['token']}") as ws:
        assert ws.receive_json()["type"] == "snapshot"
        messages = [ws.receive_json()["message"] for _ in range(2)]

    assert messages == ["first line", "second line"]


def test_replay_can_be_disabled(app_client, _fake_redis):
    from core.events import log_event, publish, terminal_event

    a = _register(app_client, "alpha", "alpha-ws.example")
    scan_id = _make_scan(a["org_id"], a["domain"])
    publish(scan_id, log_event(scan_id, "old line"))

    with app_client.websocket_connect(
        f"/ws/scan/{scan_id}?token={a['token']}&replay=0"
    ) as ws:
        assert ws.receive_json()["type"] == "snapshot"
        # With replay off, the backlog is skipped; only new events arrive.
        publish(scan_id, terminal_event(scan_id, "completed"))
        event = ws.receive_json()
        assert event["type"] == "end"


def test_live_events_stream_through(app_client, _fake_redis):
    """A line published while the socket is open must reach the client."""
    from core.events import log_event, publish

    a = _register(app_client, "alpha", "alpha-ws.example")
    scan_id = _make_scan(a["org_id"], a["domain"])

    with app_client.websocket_connect(f"/ws/scan/{scan_id}?token={a['token']}") as ws:
        assert ws.receive_json()["type"] == "snapshot"

        publish(scan_id, log_event(scan_id, "discovered api.example.com"))
        event = ws.receive_json()

    assert event["type"] == "log"
    assert event["message"] == "discovered api.example.com"


def test_terminal_event_closes_the_stream(app_client, _fake_redis):
    from core.events import publish, terminal_event

    a = _register(app_client, "alpha", "alpha-ws.example")
    scan_id = _make_scan(a["org_id"], a["domain"])

    with app_client.websocket_connect(f"/ws/scan/{scan_id}?token={a['token']}") as ws:
        assert ws.receive_json()["type"] == "snapshot"
        publish(scan_id, terminal_event(scan_id, "completed", findings_count=3))

        end = ws.receive_json()
        assert end["type"] == "end"

        # The server breaks its loop after "end"; the socket then closes.
        with pytest.raises(WebSocketDisconnect):
            while True:
                ws.receive_json()


def test_finished_scan_ends_immediately(app_client, _fake_redis):
    """Reconnecting to a completed scan replays its log and closes cleanly."""
    from core.events import log_event, publish
    from models import ScanStatus

    a = _register(app_client, "alpha", "alpha-ws.example")
    scan_id = _make_scan(a["org_id"], a["domain"], status=ScanStatus.COMPLETED)
    publish(scan_id, log_event(scan_id, "archived line"))

    with app_client.websocket_connect(f"/ws/scan/{scan_id}?token={a['token']}") as ws:
        assert ws.receive_json()["type"] == "snapshot"
        assert ws.receive_json()["message"] == "archived line"
        assert ws.receive_json()["type"] == "end"


def test_malformed_event_does_not_kill_the_stream(app_client, _fake_redis):
    """A junk payload on the channel is dropped, not fatal."""
    from core.events import log_event, publish, scan_channel, sync_redis

    a = _register(app_client, "alpha", "alpha-ws.example")
    scan_id = _make_scan(a["org_id"], a["domain"])

    with app_client.websocket_connect(f"/ws/scan/{scan_id}?token={a['token']}") as ws:
        assert ws.receive_json()["type"] == "snapshot"

        sync_redis().publish(scan_channel(scan_id), "this is not json{{")
        publish(scan_id, log_event(scan_id, "still alive"))

        event = ws.receive_json()

    assert event["message"] == "still alive"
