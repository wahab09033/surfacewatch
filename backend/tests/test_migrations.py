"""The migrations actually run, and produce the schema the models describe.

Nothing else in this suite exercises Alembic. ``conftest._schema`` builds the
test database with ``Base.metadata.create_all``, which reads the models and
writes DDL from them — so it is structurally incapable of catching a migration
that is missing a column, drops a constraint, or forgets to create its enum
type. Every one of those would pass the suite and fail on a real deploy, at the
one moment there is no going back.

So this module runs the real thing: a scratch database, ``alembic upgrade
head``, then assertions about the resulting schema taken from the database
itself rather than from the models. It then downgrades, checks the downgrade
cleaned up after itself, and upgrades again.

The assertions are deliberately about *properties that would break at runtime*
— the enum's label order, the FK actions, whether the check constraints actually
reject bad rows — rather than a full column-by-column mirror of the models,
which would just be the models restated.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest
import sqlalchemy as sa

# A separate database from the suite's own, so neither can truncate the other.
SCRATCH_DB = "surfacewatch_migration_check"


def _admin_url() -> str:
    from config import get_settings

    settings = get_settings()
    return settings.sync_database_url.rsplit("/", 1)[0] + "/postgres"


def _scratch_url() -> str:
    from config import get_settings

    settings = get_settings()
    return settings.sync_database_url.rsplit("/", 1)[0] + f"/{SCRATCH_DB}"


def _alembic(*args: str) -> subprocess.CompletedProcess:
    """Run alembic against the scratch database, in a child process.

    A subprocess rather than ``alembic.command``: the command API mutates the
    process-global ``Config`` and logging state, and this suite shares a
    process with 300 other tests. POSTGRES_DB in the child's environment is
    what points it at the scratch database.
    """
    env = dict(os.environ, POSTGRES_DB=SCRATCH_DB)
    return subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        capture_output=True,
        text=True,
        env=env,
    )


@pytest.fixture(scope="module")
def migrated():
    """A scratch database at head, torn down afterwards."""
    from db.database import sync_engine  # noqa: F401  (ensures models are imported)

    admin = sa.create_engine(_admin_url(), isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(sa.text(f'DROP DATABASE IF EXISTS "{SCRATCH_DB}" WITH (FORCE)'))
        conn.execute(sa.text(f'CREATE DATABASE "{SCRATCH_DB}"'))
    admin.dispose()

    try:
        result = _alembic("upgrade", "head")
        assert result.returncode == 0, result.stdout + result.stderr

        engine = sa.create_engine(_scratch_url())
        yield engine
        engine.dispose()
    finally:
        admin = sa.create_engine(_admin_url(), isolation_level="AUTOCOMMIT")
        with admin.connect() as conn:
            conn.execute(sa.text(f'DROP DATABASE IF EXISTS "{SCRATCH_DB}" WITH (FORCE)'))
        admin.dispose()


def test_upgrade_head_creates_the_schedule_table(migrated):
    columns = {c["name"] for c in sa.inspect(migrated).get_columns("scan_schedules")}
    assert columns == {
        "id",
        "org_id",
        "created_by",
        "name",
        "target",
        "config",
        "cadence",
        "hour_utc",
        "weekday",
        "is_enabled",
        "next_run_at",
        "last_run_at",
        "last_scan_id",
        "consecutive_failures",
        "disabled_reason",
        "created_at",
        "updated_at",
    }


def test_the_cadence_enum_is_native_and_ordered(migrated):
    """The order matters: ``values_callable`` writes lower-case values, and a
    migration that listed them differently from the Python enum would make
    every stored value ambiguous."""
    with migrated.connect() as conn:
        labels = (
            conn.execute(
                sa.text(
                    "SELECT enumlabel FROM pg_enum e JOIN pg_type t ON t.oid = e.enumtypid "
                    "WHERE t.typname = 'scan_cadence' ORDER BY e.enumsortorder"
                )
            )
            .scalars()
            .all()
        )
    assert list(labels) == ["hourly", "daily", "weekly"]


def test_the_dispatcher_index_exists(migrated):
    indexes = {i["name"] for i in sa.inspect(migrated).get_indexes("scan_schedules")}
    assert {
        "ix_scan_schedules_due",
        "ix_scan_schedules_org_id",
        "ix_scan_schedules_next_run_at",
    } <= indexes


def test_the_foreign_key_actions_are_what_the_model_asked_for(migrated):
    """Deleting a user must not delete their schedules, and the retention sweep
    deleting an old scan must not delete the schedule that produced it."""
    fks = {fk["referred_table"]: fk for fk in sa.inspect(migrated).get_foreign_keys("scan_schedules")}
    assert set(fks) == {"organisations", "users", "scans"}
    assert fks["organisations"]["options"].get("ondelete") == "CASCADE"
    assert fks["users"]["options"].get("ondelete") == "SET NULL"
    assert fks["scans"]["options"].get("ondelete") == "SET NULL"


def test_the_check_constraints_actually_reject_bad_rows(migrated):
    """A constraint that is declared but not enforced is worse than none: the
    dispatcher trusts ``hour_utc`` enough to pass it to ``datetime.replace``.
    """
    with migrated.connect() as conn:
        org_id = conn.execute(
            sa.text(
                "INSERT INTO organisations (id, name, domain, verified_domains, is_active, "
                "created_at, updated_at) VALUES (gen_random_uuid(), 'm', 'm.example', '[]', "
                "true, now(), now()) RETURNING id"
            )
        ).scalar_one()
        conn.commit()

        def _insert(cadence: str, hour: int, weekday: int | None) -> None:
            conn.execute(
                sa.text(
                    "INSERT INTO scan_schedules (id, org_id, name, target, config, cadence, "
                    "hour_utc, weekday, is_enabled, next_run_at, consecutive_failures, "
                    "created_at, updated_at) VALUES (gen_random_uuid(), :o, 'n', 'm.example', "
                    "'{}', :c, :h, :w, true, now(), 0, now(), now())"
                ),
                {"o": org_id, "c": cadence, "h": hour, "w": weekday},
            )
            conn.commit()

        with pytest.raises(sa.exc.IntegrityError):
            _insert("daily", 25, None)
        conn.rollback()

        with pytest.raises(sa.exc.IntegrityError):
            _insert("weekly", 3, None)
        conn.rollback()

        with pytest.raises(sa.exc.IntegrityError):
            _insert("weekly", 3, 9)
        conn.rollback()

        # And the valid shapes are accepted, so the constraints are not simply
        # rejecting everything.
        _insert("hourly", 0, None)
        _insert("daily", 23, None)
        _insert("weekly", 3, 0)
        _insert("weekly", 3, 6)


def test_downgrade_removes_the_table_and_the_enum(migrated):
    """``down_revision`` chaining is only proven by walking it.

    A downgrade that leaves the type behind makes the next upgrade fail with
    "type already exists", which turns a rollback into an outage.
    """
    result = _alembic("downgrade", "-1")
    assert result.returncode == 0, result.stdout + result.stderr

    try:
        assert "scan_schedules" not in sa.inspect(migrated).get_table_names()
        with migrated.connect() as conn:
            remaining = conn.execute(
                sa.text("SELECT count(*) FROM pg_type WHERE typname = 'scan_cadence'")
            ).scalar_one()
        assert remaining == 0, "the enum type outlived its table"

        # Back up again, which is what proves the downgrade was clean.
        result = _alembic("upgrade", "head")
        assert result.returncode == 0, result.stdout + result.stderr
        assert "scan_schedules" in sa.inspect(migrated).get_table_names()
    finally:
        # The following tests in this module need the schema present; if an
        # assertion above failed the database is left mid-flight, so put the
        # table back unconditionally.
        _alembic("upgrade", "head")
