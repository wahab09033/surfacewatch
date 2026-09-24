"""Scheduled scans: cadence arithmetic, the dispatcher, retention, re-verification.

The dispatcher is the only code in the system that creates work with no user
behind it, so the assertions worth reading twice are the ones about what it
refuses to do:

* a schedule whose domain is no longer verified is **disabled**, not quietly run
  — a revoked domain must stop producing scans, and the check has to happen on
  every tick rather than only at creation;
* a schedule for a tenant already at their concurrency cap is skipped, and its
  window is *not* held back to fire later (that is the catch-up behaviour
  ``next_run_at`` exists to prevent);
* every one of those paths still advances ``next_run_at`` first, so a failure
  mid-tick cannot make the same window fire again on the next one.

The cadence helper is exercised as a pure function, with ``after`` passed in.
The alternative — freezegun, or asserting "some time in the next hour" — cannot
pin the weekly weekday arithmetic, which is the part most likely to be wrong.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from models.base import ScanCadence
from models.scan_schedule import initial_next_run, next_occurrence

# No module-level asyncio mark: pytest.ini sets asyncio_mode = auto, and marking
# the module would also mark the pure cadence tests, which are deliberately
# synchronous.

SCHEDULES = "/api/schedules"
PASSWORD = "correct-horse-battery-staple-7"

# 2026-09-24 is a Thursday. Fixed rather than "now" so the weekday cases below
# are readable and cannot drift with the calendar.
THURSDAY = datetime(2026, 9, 24, 10, 0, tzinfo=timezone.utc)


def utc(*args: int) -> datetime:
    return datetime(*args, tzinfo=timezone.utc)


# --- cadence arithmetic -----------------------------------------------------


def test_hourly_lands_on_the_top_of_the_next_hour():
    assert next_occurrence(ScanCadence.HOURLY, 3, None, after=utc(2026, 9, 24, 10, 30)) == utc(
        2026, 9, 24, 11, 0
    )


def test_hourly_from_exactly_the_hour_moves_forward():
    """Strictly after, or the tick that fired would fire again immediately."""
    assert next_occurrence(ScanCadence.HOURLY, 3, None, after=utc(2026, 9, 24, 10, 0)) == utc(
        2026, 9, 24, 11, 0
    )


def test_hourly_ignores_the_configured_hour():
    """An hourly schedule that also pinned an hour would be a daily one."""
    assert next_occurrence(ScanCadence.HOURLY, 22, None, after=utc(2026, 9, 24, 10, 0)) == utc(
        2026, 9, 24, 11, 0
    )


def test_daily_before_the_hour_is_today():
    assert next_occurrence(ScanCadence.DAILY, 3, None, after=utc(2026, 9, 24, 1, 0)) == utc(
        2026, 9, 24, 3, 0
    )


def test_daily_after_the_hour_is_tomorrow():
    assert next_occurrence(ScanCadence.DAILY, 3, None, after=utc(2026, 9, 24, 5, 0)) == utc(
        2026, 9, 25, 3, 0
    )


def test_daily_at_exactly_the_hour_is_tomorrow():
    assert next_occurrence(ScanCadence.DAILY, 3, None, after=utc(2026, 9, 24, 3, 0)) == utc(
        2026, 9, 25, 3, 0
    )


def test_weekly_lands_on_the_requested_weekday():
    # Thursday -> Monday.
    assert next_occurrence(ScanCadence.WEEKLY, 3, 0, after=THURSDAY) == utc(2026, 9, 28, 3, 0)


def test_weekly_on_the_same_day_before_the_hour_is_today():
    # Thursday 10:00, weekly Thursday 22:00 -> tonight.
    assert next_occurrence(ScanCadence.WEEKLY, 22, 3, after=THURSDAY) == utc(2026, 9, 24, 22, 0)


def test_weekly_on_the_same_day_after_the_hour_is_next_week():
    assert next_occurrence(ScanCadence.WEEKLY, 3, 3, after=THURSDAY) == utc(2026, 10, 1, 3, 0)


def test_weekly_wraps_around_the_week():
    # Thursday -> Wednesday means the next one is in six days, not the day before.
    assert next_occurrence(ScanCadence.WEEKLY, 3, 2, after=THURSDAY) == utc(2026, 9, 30, 3, 0)


def test_weekly_without_a_weekday_is_refused():
    with pytest.raises(ValueError, match="weekday"):
        next_occurrence(ScanCadence.WEEKLY, 3, None, after=THURSDAY)


def test_naive_datetime_is_refused():
    """A naive ``after`` is a caller bug, and a silent one: it would be read as
    UTC and shift every schedule by the caller's offset."""
    with pytest.raises(ValueError, match="timezone-aware"):
        next_occurrence(ScanCadence.DAILY, 3, None, after=datetime(2026, 9, 24, 10, 0))


def test_a_non_utc_input_is_converted_not_reinterpreted():
    """``hour_utc`` means UTC. A +05:00 caller must land on 03:00 UTC, not 03:00 local."""
    karachi = timezone(timedelta(hours=5))
    after = datetime(2026, 9, 24, 1, 0, tzinfo=karachi)  # 2026-09-23 20:00 UTC
    assert next_occurrence(ScanCadence.DAILY, 3, None, after=after) == utc(2026, 9, 24, 3, 0)


def test_a_long_outage_does_not_accumulate_missed_runs():
    """A week of downtime produces one scan, not seven.

    Each call advances from the *previous* result, which is what the dispatcher
    does on consecutive ticks. However far behind the schedule has fallen, the
    next run is always the next future slot.
    """
    after = utc(2026, 9, 24, 3, 0)
    # Three days late.
    nxt = next_occurrence(ScanCadence.DAILY, 3, None, after=utc(2026, 9, 27, 9, 0))
    assert nxt == utc(2026, 9, 28, 3, 0)
    assert (nxt - after).days == 4  # one slot, four days on — not four slots


def test_initial_next_run_is_not_now():
    """Saving a schedule must not itself start a scan."""
    now = utc(2026, 9, 24, 10, 0)
    assert initial_next_run(ScanCadence.DAILY, 3, None, now=now) == utc(2026, 9, 25, 3, 0)
    assert initial_next_run(ScanCadence.HOURLY, 0, None, now=now) == utc(2026, 9, 24, 11, 0)


# --- helpers ----------------------------------------------------------------


async def _register(client, slug: str, domain: str) -> dict:
    resp = await client.post(
        "/api/auth/register",
        json={
            "org_name": f"{slug} corp",
            "domain": domain,
            "email": f"owner@{domain}",
            "password": PASSWORD,
            "full_name": f"{slug} owner",
        },
    )
    assert resp.status_code == 201, resp.text
    return {"headers": {"Authorization": f"Bearer {resp.json()['access_token']}"}, "domain": domain}


def set_verified_domains(org_domain: str, verified: list[str]) -> None:
    """Overwrite an organisation's scanning authority, bypassing the TXT challenge.

    The DNS flow is covered by test_domain_verification.py. These tests are
    about what the scheduler does with the *result* of that flow, so re-running
    it here would only couple them to it.

    Keyed on the org's ``domain`` column and writing ``verified``, which are
    different things on purpose: withdrawing authority means the org keeps its
    identity but loses the scope derived from it.
    """
    import sqlalchemy as sa

    from db.database import sync_engine

    with sync_engine.begin() as conn:
        conn.execute(
            sa.text(
                "UPDATE organisations SET verified_domains = CAST(:d AS jsonb) WHERE domain = :dom"
            ),
            {"d": json.dumps(verified), "dom": org_domain},
        )


def grant_domain(org_domain: str) -> None:
    """Give an org authority over its own domain."""
    set_verified_domains(org_domain, [org_domain])


def force_due(schedule_id: str, *, when: datetime | None = None) -> None:
    """Backdate a schedule's window so the next dispatcher tick picks it up."""
    import sqlalchemy as sa

    from db.database import sync_engine

    with sync_engine.begin() as conn:
        conn.execute(
            sa.text("UPDATE scan_schedules SET next_run_at = :t WHERE id = :id"),
            {"t": when or (datetime.now(timezone.utc) - timedelta(hours=1)), "id": uuid.UUID(schedule_id)},
        )


def schedules_in_db() -> list[dict]:
    import sqlalchemy as sa

    from db.database import sync_engine

    with sync_engine.begin() as conn:
        rows = conn.execute(
            sa.text(
                "SELECT name, is_enabled, next_run_at, last_run_at, last_scan_id, "
                "consecutive_failures, disabled_reason FROM scan_schedules"
            )
        ).mappings()
        return [dict(r) for r in rows]


def scans_in_db() -> list[dict]:
    import sqlalchemy as sa

    from db.database import sync_engine

    with sync_engine.begin() as conn:
        rows = conn.execute(
            sa.text("SELECT target, status, created_by, config FROM scans ORDER BY created_at")
        ).mappings()
        return [dict(r) for r in rows]


class _FakeTask:
    def __init__(self, task_id: str) -> None:
        self.id = task_id


@pytest.fixture
def dispatched(monkeypatch) -> list[dict]:
    """Capture what the scheduler hands to the broker, instead of publishing it.

    conftest puts Celery in eager mode, so a real ``dispatch_scan`` would run the
    entire scan pipeline inline — real DNS lookups and real port scans, inside a
    unit test. Dispatching itself is covered by the scan-route tests.
    """
    calls: list[dict] = []

    def _dispatch(*, scan_id, org_id, target, config):
        calls.append({"scan_id": scan_id, "org_id": org_id, "target": target, "config": config})
        return _FakeTask(f"task-{len(calls)}")

    import workers.orchestrator as orchestrator

    monkeypatch.setattr(orchestrator, "dispatch_scan", _dispatch)
    return calls


@pytest.fixture
async def org(client) -> dict:
    ctx = await _register(client, "alpha", "alpha-corp.example")
    grant_domain("alpha-corp.example")
    return ctx


async def _create_schedule(client, ctx: dict, **overrides) -> dict:
    body = {
        "name": "nightly",
        "target": "alpha-corp.example",
        "cadence": "daily",
        "hour_utc": 3,
        **overrides,
    }
    resp = await client.post(SCHEDULES, json=body, headers=ctx["headers"])
    assert resp.status_code == 201, resp.text
    return resp.json()


# --- creating schedules -----------------------------------------------------


async def test_a_new_schedule_is_not_due_immediately(client, org):
    schedule = await _create_schedule(client, org)
    assert schedule["is_enabled"] is True
    assert schedule["last_run_at"] is None

    from models.base import utcnow

    assert datetime.fromisoformat(schedule["next_run_at"]) > utcnow()


async def test_schedule_text_is_written_once_server_side(client, org):
    daily = await _create_schedule(client, org, cadence="daily", hour_utc=3)
    assert daily["schedule_text"] == "every day at 03:00 UTC"

    weekly = await _create_schedule(client, org, name="weekly", cadence="weekly", weekday=0)
    assert weekly["schedule_text"] == "every Monday at 03:00 UTC"

    hourly = await _create_schedule(client, org, name="hourly", cadence="hourly")
    assert hourly["schedule_text"] == "every hour"


async def test_weekly_without_a_weekday_is_rejected(client, org):
    resp = await client.post(
        SCHEDULES,
        json={"name": "w", "target": "alpha-corp.example", "cadence": "weekly"},
        headers=org["headers"],
    )
    assert resp.status_code == 422, resp.text


async def test_the_weekday_is_cleared_when_the_cadence_leaves_weekly(client, org):
    """Switching weekly -> daily must not leave a day behind.

    A stale weekday is invisible in the UI for a daily schedule, and is then
    silently inherited if the user switches back to weekly.
    """
    schedule = await _create_schedule(client, org, cadence="weekly", weekday=4)
    assert schedule["weekday"] == 4

    resp = await client.patch(
        f"{SCHEDULES}/{schedule['id']}", json={"cadence": "daily"}, headers=org["headers"]
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["weekday"] is None


async def test_an_out_of_scope_target_is_refused(client, org, monkeypatch):
    """CONFTEST SETS allow_arbitrary_targets=true, so it has to be turned off.

    Without this override every target is in scope and the assertion below
    proves nothing.
    """
    from config import settings

    monkeypatch.setattr(settings, "allow_arbitrary_targets", False)

    resp = await client.post(
        SCHEDULES,
        json={"name": "nope", "target": "someone-else.example", "cadence": "daily"},
        headers=org["headers"],
    )
    assert resp.status_code == 403, resp.text


async def test_the_target_cannot_be_changed_by_patch(client, org):
    """Repointing a schedule would carry its authorisation to a new host."""
    schedule = await _create_schedule(client, org)
    resp = await client.patch(
        f"{SCHEDULES}/{schedule['id']}",
        json={"target": "elsewhere.example"},
        headers=org["headers"],
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["target"] == "alpha-corp.example"


async def test_another_org_cannot_see_or_touch_the_schedule(client, org):
    schedule = await _create_schedule(client, org)
    other = await _register(client, "beta", "beta-corp.example")

    assert (await client.get(f"{SCHEDULES}/{schedule['id']}", headers=other["headers"])).status_code == 404
    assert (
        await client.patch(
            f"{SCHEDULES}/{schedule['id']}", json={"name": "hijack"}, headers=other["headers"]
        )
    ).status_code == 404
    assert (
        await client.delete(f"{SCHEDULES}/{schedule['id']}", headers=other["headers"])
    ).status_code == 404

    listing = await client.get(SCHEDULES, headers=other["headers"])
    assert listing.json()["items"] == []


# --- the dispatcher ---------------------------------------------------------


async def test_a_due_schedule_creates_one_scan_and_advances(client, org, dispatched):
    from models.base import utcnow
    from workers.scheduler import dispatch_due_scans

    schedule = await _create_schedule(client, org, cadence="daily", hour_utc=3)
    force_due(schedule["id"])

    counters = dispatch_due_scans(now=utcnow())

    assert counters == {"due": 1, "queued": 1, "skipped": 0, "disabled": 0, "failed": 0}
    assert len(dispatched) == 1
    assert dispatched[0]["target"] == "alpha-corp.example"

    scans = scans_in_db()
    assert len(scans) == 1
    assert scans[0]["status"] == "queued"
    # NULL author: no user asked for this run, and the person who created the
    # schedule may have left since.
    assert scans[0]["created_by"] is None

    row = schedules_in_db()[0]
    assert row["last_scan_id"] is not None
    assert row["last_run_at"] is not None
    # Advanced past now, so the next tick does not fire the same window again.
    assert row["next_run_at"].replace(tzinfo=timezone.utc) > utcnow()


async def test_a_disabled_schedule_is_never_dispatched(client, org, dispatched):
    from models.base import utcnow
    from workers.scheduler import dispatch_due_scans

    schedule = await _create_schedule(client, org)
    await client.patch(
        f"{SCHEDULES}/{schedule['id']}", json={"is_enabled": False}, headers=org["headers"]
    )
    force_due(schedule["id"])

    counters = dispatch_due_scans(now=utcnow())
    assert counters["due"] == 0
    assert dispatched == []
    assert scans_in_db() == []


async def test_a_future_schedule_is_not_dispatched(client, org, dispatched):
    from models.base import utcnow
    from workers.scheduler import dispatch_due_scans

    await _create_schedule(client, org)
    assert dispatch_due_scans(now=utcnow())["due"] == 0
    assert dispatched == []


async def test_running_the_same_tick_twice_does_not_double_dispatch(client, org, dispatched):
    """The advance-before-dispatch ordering is what makes the tick idempotent."""
    from models.base import utcnow
    from workers.scheduler import dispatch_due_scans

    schedule = await _create_schedule(client, org)
    force_due(schedule["id"])
    now = utcnow()

    assert dispatch_due_scans(now=now)["queued"] == 1
    assert dispatch_due_scans(now=now)["queued"] == 0
    assert len(dispatched) == 1
    assert len(scans_in_db()) == 1


async def test_a_revoked_domain_disables_the_schedule(client, org, dispatched, monkeypatch):
    """The security assertion: revoked scope stops the schedule, it does not
    just make this one run fail.

    The check runs on every tick rather than only at creation because
    verification is revocable — a schedule saved while a domain was verified
    must not keep scanning it after the domain is withdrawn.
    """
    from config import settings
    from models.base import utcnow
    from workers.scheduler import dispatch_due_scans

    monkeypatch.setattr(settings, "allow_arbitrary_targets", False)

    schedule = await _create_schedule(client, org)
    force_due(schedule["id"])

    # Withdraw the authority the schedule was created under: the org keeps its
    # identity, but its scope no longer covers its own domain.
    set_verified_domains("alpha-corp.example", ["unrelated.example"])

    counters = dispatch_due_scans(now=utcnow())

    assert counters["disabled"] == 1
    assert counters["queued"] == 0
    assert dispatched == []
    assert scans_in_db() == []

    row = schedules_in_db()[0]
    assert row["is_enabled"] is False
    assert "no longer authorised" in row["disabled_reason"]
    # Still advanced: a disabled schedule must not be re-evaluated every tick
    # forever against a window in the past.
    assert row["next_run_at"] is not None


async def test_a_tenant_at_the_concurrency_cap_is_skipped_not_queued(
    client, org, dispatched, monkeypatch
):
    """The window is missed, not held back.

    Holding it would hand the tenant a burst of scans the moment the cap frees
    up, which is exactly the catch-up behaviour the schedule design avoids.
    """
    from config import settings
    from models.base import utcnow
    from workers.scheduler import dispatch_due_scans

    schedule = await _create_schedule(client, org)
    force_due(schedule["id"])
    monkeypatch.setattr(settings, "max_concurrent_scans_per_org", 0)

    counters = dispatch_due_scans(now=utcnow())

    assert counters["skipped"] == 1
    assert counters["queued"] == 0
    assert dispatched == []
    assert scans_in_db() == []

    from models.base import utcnow as now

    assert schedules_in_db()[0]["next_run_at"].replace(tzinfo=timezone.utc) > now()


async def test_two_schedules_for_one_org_respect_the_cap_together(
    client, org, dispatched, monkeypatch
):
    """The count is incremented in memory as the tick queues work.

    Two schedules for the same org in one tick would both read the same
    pre-tick count, and together exceed the cap the setting exists to enforce.
    """
    from config import settings
    from models.base import utcnow
    from workers.scheduler import dispatch_due_scans

    first = await _create_schedule(client, org, name="one")
    second = await _create_schedule(client, org, name="two")
    force_due(first["id"])
    force_due(second["id"])
    monkeypatch.setattr(settings, "max_concurrent_scans_per_org", 1)

    counters = dispatch_due_scans(now=utcnow())

    assert counters == {"due": 2, "queued": 1, "skipped": 1, "disabled": 0, "failed": 0}
    assert len(dispatched) == 1


async def test_a_broker_failure_fails_the_scan_and_counts_against_the_schedule(
    client, org, monkeypatch
):
    """A scan row committed before a failed publish must not sit queued forever.

    It would count against the org's concurrency limit and show the customer a
    scan no worker will ever run.
    """
    from models.base import utcnow
    from workers.scheduler import dispatch_due_scans

    def _boom(**_kwargs):
        raise ConnectionError("redis is down")

    import workers.orchestrator as orchestrator

    monkeypatch.setattr(orchestrator, "dispatch_scan", _boom)

    schedule = await _create_schedule(client, org)
    force_due(schedule["id"])

    counters = dispatch_due_scans(now=utcnow())

    assert counters["failed"] == 1
    assert counters["queued"] == 0

    scans = scans_in_db()
    assert scans[0]["status"] == "failed"
    assert "ConnectionError" in _scan_error()

    row = schedules_in_db()[0]
    assert row["consecutive_failures"] == 1
    # Not disabled yet — one failure is an incident, not a pattern.
    assert row["is_enabled"] is True
    assert row["disabled_reason"] is None


def _scan_error() -> str:
    import sqlalchemy as sa

    from db.database import sync_engine

    with sync_engine.begin() as conn:
        return conn.execute(sa.text("SELECT error FROM scans LIMIT 1")).scalar_one()


async def test_repeated_broker_failures_disable_the_schedule(client, org, monkeypatch):
    from config import settings
    from models.base import utcnow
    from workers.scheduler import dispatch_due_scans

    def _boom(**_kwargs):
        raise ConnectionError("redis is down")

    import workers.orchestrator as orchestrator

    monkeypatch.setattr(orchestrator, "dispatch_scan", _boom)
    monkeypatch.setattr(settings, "schedule_max_consecutive_failures", 3)

    schedule = await _create_schedule(client, org)
    now = utcnow()

    for _ in range(3):
        force_due(schedule["id"])
        dispatch_due_scans(now=now)

    row = schedules_in_db()[0]
    assert row["consecutive_failures"] == 3
    assert row["is_enabled"] is False
    # Autodisabling without a reason reads as a bug to the customer.
    assert "consecutive failures" in row["disabled_reason"]


async def test_a_recovered_broker_clears_the_failure_count(client, org, dispatched, monkeypatch):
    from models.base import utcnow
    from workers.scheduler import dispatch_due_scans

    calls = {"n": 0}

    def _flaky(**_kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise ConnectionError("redis is down")
        return _FakeTask("task-2")

    import workers.orchestrator as orchestrator

    monkeypatch.setattr(orchestrator, "dispatch_scan", _flaky)

    schedule = await _create_schedule(client, org)
    now = utcnow()

    force_due(schedule["id"])
    dispatch_due_scans(now=now)
    assert schedules_in_db()[0]["consecutive_failures"] == 1

    force_due(schedule["id"])
    dispatch_due_scans(now=now)
    # Consecutive, not lifetime.
    assert schedules_in_db()[0]["consecutive_failures"] == 0


# --- run now ----------------------------------------------------------------


async def test_run_now_queues_a_scan_without_moving_the_cadence(client, org, dispatched):
    schedule = await _create_schedule(client, org, cadence="daily", hour_utc=3)
    before = schedule["next_run_at"]

    resp = await client.post(f"{SCHEDULES}/{schedule['id']}/run", headers=org["headers"])
    assert resp.status_code == 200, resp.text

    assert len(dispatched) == 1
    assert len(scans_in_db()) == 1
    # "Also run now", not "shift the schedule".
    assert resp.json()["next_run_at"] == before


# --- retention --------------------------------------------------------------


async def test_retention_is_off_by_default():
    """The sweeps that can destroy security history do nothing until asked."""
    from workers.scheduler import prune_old_data

    assert prune_old_data() == {"scan_logs": 0, "scans": 0, "reports": 0, "report_files": 0}


def _seed_scan_with_log(
    *, status: str, log_age_days: int, scan_age_days: int = 0
) -> tuple[uuid.UUID, uuid.UUID]:
    """Insert one org, one scan and one log line, aged to order."""
    import sqlalchemy as sa

    from db.database import sync_engine

    org_id, scan_id = uuid.uuid4(), uuid.uuid4()
    old = datetime.now(timezone.utc) - timedelta(days=log_age_days)
    created = datetime.now(timezone.utc) - timedelta(days=scan_age_days)
    with sync_engine.begin() as conn:
        conn.execute(
            sa.text(
                "INSERT INTO organisations (id, name, domain, verified_domains, is_active, "
                "created_at, updated_at) VALUES (:id, 'x', 'x.example', '[]', true, now(), now())"
            ),
            {"id": org_id},
        )
        conn.execute(
            sa.text(
                "INSERT INTO scans (id, org_id, target, status, config, progress, "
                "assets_discovered, findings_count, created_at, updated_at) VALUES "
                "(:id, :org, 'x.example', :status, '{}', 0, 0, 0, :created, :created)"
            ),
            {"id": scan_id, "org": org_id, "status": status, "created": created},
        )
        conn.execute(
            sa.text(
                "INSERT INTO scan_logs (id, scan_id, timestamp, message, level) VALUES "
                "(:id, :scan, :ts, 'hello', 'info')"
            ),
            {"id": uuid.uuid4(), "scan": scan_id, "ts": old},
        )
    return org_id, scan_id


def _log_count() -> int:
    import sqlalchemy as sa

    from db.database import sync_engine

    with sync_engine.begin() as conn:
        return conn.execute(sa.text("SELECT count(*) FROM scan_logs")).scalar_one()


async def test_old_logs_are_pruned(monkeypatch):
    from config import settings
    from workers.scheduler import prune_old_data

    _seed_scan_with_log(status="completed", log_age_days=40)
    monkeypatch.setattr(settings, "retention_scan_log_days", 30)

    assert prune_old_data()["scan_logs"] == 1
    assert _log_count() == 0


async def test_recent_logs_survive(monkeypatch):
    from config import settings
    from workers.scheduler import prune_old_data

    _seed_scan_with_log(status="completed", log_age_days=2)
    monkeypatch.setattr(settings, "retention_scan_log_days", 30)

    assert prune_old_data()["scan_logs"] == 0
    assert _log_count() == 1


async def test_a_running_scans_logs_are_never_pruned(monkeypatch):
    """A scan capped at an hour should never hit this, but the cost of being
    wrong is a live scan whose history vanishes mid-run."""
    from config import settings
    from workers.scheduler import prune_old_data

    _seed_scan_with_log(status="running", log_age_days=40)
    monkeypatch.setattr(settings, "retention_scan_log_days", 30)

    assert prune_old_data()["scan_logs"] == 0
    assert _log_count() == 1


async def test_pruning_scans_takes_their_logs_with_them(monkeypatch):
    """The FK cascade, not the log sweep.

    The log sweep is switched off here so the only thing that can remove those
    rows is the cascade from deleting the scan — with both enabled this would
    pass even if the cascade were missing entirely.
    """
    from config import settings
    from workers.scheduler import prune_old_data

    _seed_scan_with_log(status="completed", log_age_days=40, scan_age_days=40)
    monkeypatch.setattr(settings, "retention_scan_days", 30)
    monkeypatch.setattr(settings, "retention_scan_log_days", 0)

    assert prune_old_data() == {"scan_logs": 0, "scans": 1, "reports": 0, "report_files": 0}
    assert _log_count() == 0


async def test_recent_scans_are_kept(monkeypatch):
    from config import settings
    from workers.scheduler import prune_old_data

    _seed_scan_with_log(status="completed", log_age_days=1, scan_age_days=1)
    monkeypatch.setattr(settings, "retention_scan_days", 30)
    monkeypatch.setattr(settings, "retention_scan_log_days", 0)

    assert prune_old_data()["scans"] == 0
    assert _log_count() == 1
