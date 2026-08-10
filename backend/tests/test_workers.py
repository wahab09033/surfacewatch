"""Worker-layer tests.

The claim worth proving here is idempotency: a nightly re-scan must update the
findings it already knows about rather than growing a duplicate row every time.
That is enforced by ``Finding.build_fingerprint`` plus an ON CONFLICT upsert
against ``uq_findings_org_fingerprint``, so it is tested against real Postgres.

The port scanner is pointed at a socket this test opens on the loopback
interface, so nothing outside the machine is ever contacted.
"""

from __future__ import annotations

import socket
import threading
import uuid

import pytest

from db.database import session_scope
from models import Asset, Finding, Organisation, Scan, ScanLog, ScanStatus, Severity


# --- helpers ----------------------------------------------------------------


@pytest.fixture
def org(_clean_tables) -> uuid.UUID:
    with session_scope() as session:
        o = Organisation(
            id=uuid.uuid4(),
            name="worker test org",
            domain="worker-test.example",
            verified_domains=["worker-test.example"],
        )
        session.add(o)
        session.flush()
        return o.id


@pytest.fixture
def scan(org) -> uuid.UUID:
    with session_scope() as session:
        s = Scan(
            id=uuid.uuid4(),
            org_id=org,
            target="worker-test.example",
            status=ScanStatus.RUNNING,
            config={},
        )
        session.add(s)
        session.flush()
        return s.id


@pytest.fixture
def asset(org) -> uuid.UUID:
    with session_scope() as session:
        a = Asset(
            id=uuid.uuid4(),
            org_id=org,
            hostname="host.worker-test.example",
            ip="203.0.113.5",
        )
        session.add(a)
        session.flush()
        return a.id


@pytest.fixture
def listener():
    """A real TCP listener on an ephemeral loopback port."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(8)
    port = sock.getsockname()[1]

    stop = threading.Event()

    def _serve():
        sock.settimeout(0.3)
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
            except (TimeoutError, OSError):
                continue
            try:
                conn.sendall(b"SSH-2.0-OpenSSH_9.2\r\n")
            except OSError:
                pass
            finally:
                conn.close()

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        stop.set()
        thread.join(timeout=2)
        sock.close()


def _context(scan_id, org_id, target="host.worker-test.example"):
    from workers.context import ScanContext

    return ScanContext.load(
        scan_id=scan_id, org_id=org_id, target=target, config={}, stage="port_scanner"
    )


# --- port probing -----------------------------------------------------------


def test_probe_detects_open_and_closed_ports(org, scan, listener):
    """The asyncio prober must find a live socket and not invent dead ones."""
    import asyncio

    from workers.port_scanner import _probe_address

    # A port nobody is listening on, for the negative case.
    spare = socket.socket()
    spare.bind(("127.0.0.1", 0))
    closed_port = spare.getsockname()[1]
    spare.close()

    # _probe_address, not _scan_host: the latter resolves and refuses loopback
    # by design. This exercises the probe mechanics; the refusal is asserted in
    # test_scan_host_refuses_private_targets below.
    results = asyncio.run(_probe_address("127.0.0.1", [listener, closed_port], 2.0, 10))
    open_ports = {r["port"] for r in results if r.get("state") == "open"}

    assert listener in open_ports
    assert closed_port not in open_ports


def test_probe_reads_service_banner(org, scan, listener):
    import asyncio

    from workers.port_scanner import _probe_address

    results = asyncio.run(_probe_address("127.0.0.1", [listener], 2.0, 10))
    entry = next(r for r in results if r["port"] == listener)
    assert "OpenSSH" in (entry.get("banner") or "")


def test_scan_host_refuses_private_targets(org, scan, listener):
    """A host that resolves inward must never reach the probe layer.

    This is the DNS-rebinding guard: assert_in_scope() validated a *name* when
    the scan was created, and a name whose A record points at 127.0.0.1 or
    169.254.169.254 passes that check while still steering us at our own
    infrastructure. The listener is live, so a missing guard shows up as a
    successful scan rather than as a connection error.
    """
    import asyncio

    from core.scoring import UnsafeAddressError
    from workers.port_scanner import _scan_host

    ctx = _context(scan, org)
    for target in ("127.0.0.1", "localhost", "169.254.169.254", "10.0.0.5"):
        with pytest.raises(UnsafeAddressError):
            asyncio.run(_scan_host(ctx, target, [listener], 2.0, 10))


# --- finding upserts --------------------------------------------------------


def _record_one(ctx, asset_id, hostname, port, *, banner="redis_version:7.0.5"):
    """Record a single sensitive-service finding through the worker's own path."""
    from workers.port_scanner import _record_port_findings

    return _record_port_findings(
        ctx,
        asset_id,
        hostname,
        [{"port": port, "state": "open", "service": "redis", "banner": banner}],
    )


def test_rescan_updates_instead_of_duplicating(org, scan, asset):
    """The core idempotency guarantee: two scans, one finding row."""
    ctx = _context(scan, org)
    hostname = "host.worker-test.example"

    _record_one(ctx, asset, hostname, 6379)
    _record_one(ctx, asset, hostname, 6379)

    with session_scope() as session:
        rows = session.query(Finding).filter(Finding.org_id == org).all()
        assert len(rows) == 1, f"re-scan duplicated the finding ({len(rows)} rows)"
        assert rows[0].first_seen is not None
        assert rows[0].last_seen is not None


def test_rescan_advances_last_seen_but_keeps_first_seen(org, scan, asset):
    """A recurring issue keeps its original first_seen for age reporting."""
    ctx = _context(scan, org)
    hostname = "host.worker-test.example"

    _record_one(ctx, asset, hostname, 6379)
    with session_scope() as session:
        original = session.query(Finding).filter(Finding.org_id == org).one()
        first_seen, last_seen = original.first_seen, original.last_seen

    _record_one(ctx, asset, hostname, 6379)
    with session_scope() as session:
        updated = session.query(Finding).filter(Finding.org_id == org).one()
        assert updated.first_seen == first_seen, "first_seen must not be overwritten"
        assert updated.last_seen >= last_seen


def test_distinct_ports_produce_distinct_findings(org, scan, asset):
    ctx = _context(scan, org)
    hostname = "host.worker-test.example"

    _record_one(ctx, asset, hostname, 6379)
    _record_one(ctx, asset, hostname, 27017)

    with session_scope() as session:
        assert session.query(Finding).filter(Finding.org_id == org).count() == 2


def test_findings_are_written_with_the_owning_org(org, scan, asset):
    """Every worker-written row must carry org_id, or isolation breaks."""
    ctx = _context(scan, org)
    _record_one(ctx, asset, "host.worker-test.example", 6379)

    with session_scope() as session:
        row = session.query(Finding).one()
        assert row.org_id == org
        assert row.asset_id == asset
        assert row.scan_id == scan
        assert row.severity in set(Severity)


def test_sensitive_port_severity_is_not_info(org, scan, asset):
    """An exposed database must not be filed as informational."""
    ctx = _context(scan, org)
    _record_one(ctx, asset, "host.worker-test.example", 6379)

    with session_scope() as session:
        row = session.query(Finding).one()
        assert row.severity in (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)


def test_benign_port_records_no_finding(org, scan, asset):
    """Port 80 being open is not, by itself, a finding."""
    from workers.port_scanner import _record_port_findings

    ctx = _context(scan, org)
    recorded = _record_port_findings(
        ctx,
        asset,
        "host.worker-test.example",
        [{"port": 80, "state": "open", "service": "http", "banner": None}],
    )

    assert recorded == 0
    with session_scope() as session:
        assert session.query(Finding).count() == 0


# --- log streaming ----------------------------------------------------------


def test_log_persists_to_postgres_and_publishes(org, scan, _fake_redis):
    """ctx.log must both durably record the line and stream it."""
    from core.events import scan_history_key, sync_redis

    ctx = _context(scan, org)
    ctx.log("enumerating subdomains")

    with session_scope() as session:
        rows = session.query(ScanLog).filter(ScanLog.scan_id == scan).all()
        assert [r.message for r in rows] == ["enumerating subdomains"]

    history = sync_redis().lrange(scan_history_key(scan), 0, -1)
    assert any("enumerating subdomains" in item for item in history)


def test_debug_streams_without_persisting(org, scan, _fake_redis):
    """Verbose lines reach the UI but must not bloat the scan_logs table."""
    ctx = _context(scan, org)
    ctx.debug("probing 1/1000")

    with session_scope() as session:
        assert session.query(ScanLog).filter(ScanLog.scan_id == scan).count() == 0


def test_redis_outage_does_not_break_logging(org, scan, monkeypatch):
    """Streaming is best-effort; Postgres is the authoritative log."""
    import redis

    import core.events as events

    def _explode():
        raise redis.RedisError("redis is down")

    monkeypatch.setattr(events, "sync_redis", _explode)

    ctx = _context(scan, org)
    ctx.log("still recorded")  # must not raise

    with session_scope() as session:
        rows = session.query(ScanLog).filter(ScanLog.scan_id == scan).all()
        assert [r.message for r in rows] == ["still recorded"]


def test_counters_accumulate_on_the_scan_row(org, scan):
    ctx = _context(scan, org)
    ctx.bump_counters(assets=3, findings=2)
    ctx.bump_counters(assets=1, findings=1)

    with session_scope() as session:
        row = session.get(Scan, scan)
        assert row.assets_discovered == 4
        assert row.findings_count == 3


def test_set_stage_updates_progress(org, scan):
    ctx = _context(scan, org)
    ctx.set_stage("port_scanner", 40)

    with session_scope() as session:
        row = session.get(Scan, scan)
        assert row.current_stage == "port_scanner"
        assert row.progress == 40


def test_cancellation_is_observed_by_workers(org, scan):
    """A cancelled scan must be detectable so stages stop cooperatively."""
    ctx = _context(scan, org)
    assert ctx.is_cancelled() is False

    with session_scope() as session:
        session.get(Scan, scan).status = ScanStatus.CANCELLED

    assert ctx.is_cancelled() is True


def test_allowed_domains_comes_from_the_owning_org(org, scan):
    ctx = _context(scan, org)
    assert "worker-test.example" in ctx.allowed_domains()


# --- orchestrator -----------------------------------------------------------


def test_finalise_scan_closes_the_scan_out(org, scan, _fake_redis):
    from workers.orchestrator import finalise_scan

    finalise_scan.apply(args=(None, str(scan), str(org)))

    with session_scope() as session:
        row = session.get(Scan, scan)
        assert row.status is ScanStatus.COMPLETED
        assert row.progress == 100
        assert row.completed_at is not None


def test_finalise_scan_does_not_resurrect_a_cancelled_scan(org, scan, _fake_redis):
    """An in-flight chain finishing must not flip CANCELLED to COMPLETED."""
    from workers.orchestrator import finalise_scan

    with session_scope() as session:
        session.get(Scan, scan).status = ScanStatus.CANCELLED

    finalise_scan.apply(args=(None, str(scan), str(org)))

    with session_scope() as session:
        assert session.get(Scan, scan).status is ScanStatus.CANCELLED


def test_fail_scan_records_the_error(org, scan, _fake_redis):
    from workers.orchestrator import fail_scan

    fail_scan.apply(
        args=(None, RuntimeError("dns resolution failed"), None, str(scan), str(org))
    )

    with session_scope() as session:
        row = session.get(Scan, scan)
        assert row.status is ScanStatus.FAILED
        assert row.error
        assert row.completed_at is not None
