"""slack webhook url on organisations

Adds the per-organisation Slack incoming-webhook URL used by
workers/notifier.py to alert on critical findings.

Nullable with no default: notifications are opt-in, and an organisation with no
URL simply gets no alerts. Backfilling a placeholder would mean the notifier
had to distinguish "unset" from "set to something meaningless".

512 characters because Slack's incoming-webhook URLs run to roughly 130 today,
and a column that is merely generous costs nothing on a table with one row per
tenant.

Revision ID: 0002_slack_webhook
Revises: 0001_initial
Create Date: 2026-08-04

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0002_slack_webhook"
down_revision: Union[str, None] = "0001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "organisations",
        sa.Column("slack_webhook_url", sa.String(length=512), nullable=True),
    )


def downgrade() -> None:
    # Dropping this discards the configured webhook. That is the correct
    # behaviour for a downgrade — the column is the only place it is stored —
    # but it is not recoverable, so re-adding the integration means pasting the
    # URL in again from Slack.
    op.drop_column("organisations", "slack_webhook_url")
