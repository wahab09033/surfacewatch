"""scheduled scans

Adds ``scan_schedules``: a saved target and scan config, plus the next time it
should run. ``workers.scheduler`` reads this table on a Celery beat tick and
queues one scan per due row.

The cadence columns are three small integers and an enum rather than a cron
expression, which is a deliberate trade. A cron string is one column and no
schema, but it needs a parser at dispatch time (a new dependency), it needs a
validator to stop ``* * * * *``, and its failure mode is unbounded work rather
than an error: the org concurrency cap limits how many scans *run*, not how many
are *created*, so a minute-by-minute schedule fills the broker queue with scans
nobody will ever run and starves every other tenant. Fixed cadences make that
expression unrepresentable.

``next_run_at`` is the entire scheduling state — there is no table of future
occurrences. It is indexed alongside ``is_enabled`` because the dispatcher's
only query is "enabled and due", and that index is what keeps the tick O(due)
instead of O(all schedules).

Revision ID: 0005_scan_schedules
Revises: 0004_refresh_sessions
Create Date: 2026-09-24

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005_scan_schedules"
down_revision: Union[str, None] = "0004_refresh_sessions"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# create_type=False plus an explicit create() below, so creating the column does
# not make alembic emit a second CREATE TYPE.
scan_cadence = postgresql.ENUM("hourly", "daily", "weekly", name="scan_cadence", create_type=False)


def upgrade() -> None:
    bind = op.get_bind()
    scan_cadence.create(bind, checkfirst=True)

    op.create_table(
        "scan_schedules",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organisations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # SET NULL: an analyst leaving must not delete the organisation's
        # recurring scans. NULL also means "created by a schedule" on the Scan
        # rows this produces.
        sa.Column(
            "created_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("target", sa.String(253), nullable=False),
        sa.Column(
            "config", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")
        ),
        sa.Column("cadence", scan_cadence, nullable=False, server_default="daily"),
        sa.Column("hour_utc", sa.SmallInteger(), nullable=False, server_default="3"),
        sa.Column("weekday", sa.SmallInteger(), nullable=True),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        # SET NULL rather than CASCADE, so the retention sweep in
        # workers.scheduler can delete old scans without taking the schedule
        # that produced them with it.
        sa.Column(
            "last_scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("disabled_reason", sa.Text(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        # Enforced here as well as in the Pydantic schema: the dispatcher passes
        # hour_utc straight to datetime.replace(hour=...), so a value outside
        # 0-23 raises inside the scheduler on every tick, forever, with nothing
        # in the customer's view to explain it.
        sa.CheckConstraint("hour_utc BETWEEN 0 AND 23", name="ck_scan_schedules_hour_utc"),
        sa.CheckConstraint(
            "weekday IS NULL OR weekday BETWEEN 0 AND 6", name="ck_scan_schedules_weekday"
        ),
        sa.CheckConstraint(
            "cadence <> 'weekly' OR weekday IS NOT NULL",
            name="ck_scan_schedules_weekly_needs_weekday",
        ),
    )
    op.create_index("ix_scan_schedules_org_id", "scan_schedules", ["org_id"])
    op.create_index("ix_scan_schedules_next_run_at", "scan_schedules", ["next_run_at"])
    # The dispatcher's query, in index order.
    op.create_index(
        "ix_scan_schedules_due", "scan_schedules", ["is_enabled", "next_run_at"]
    )


def downgrade() -> None:
    # Drops every recurring scan. The scans these schedules already produced
    # stay — they are ordinary rows in ``scans`` with no dependency on this
    # table, which is why ``last_scan_id`` points the other way.
    op.drop_table("scan_schedules")

    bind = op.get_bind()
    scan_cadence.drop(bind, checkfirst=True)
