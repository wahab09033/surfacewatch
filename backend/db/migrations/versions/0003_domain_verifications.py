"""domain ownership verification

Adds ``domain_verifications``: one row per (organisation, domain) claim, holding
the DNS challenge token and the outcome of the last check.

This is the table that makes ``organisations.verified_domains`` mean something.
Before it, that column was written straight from the registration form, so any
account could claim any domain and scan it. ``verified_domains`` stays as a
denormalised cache of the VERIFIED rows here — it is read on every scan create,
every asset create, and inside every worker, and a join on that path is not worth
paying. The rows below are the record of truth.

**No data migration on ``organisations``.** Registration has always written
``verified_domains=[body.domain]``, and ``Organisation.all_domains`` used to
return ``[self.domain, *verified_domains]`` de-duplicated — the same single
element. Existing organisations therefore keep exactly the scope they had, and
only new registrations are affected. Backfilling PENDING claims for them is
deliberately not done either: it would present a challenge for a domain they are
already scanning, and revoking that access is a decision for the operator, not a
side effect of a schema upgrade. The weekly re-verification task is where those
domains eventually get asked for proof.

Revision ID: 0003_domain_verifications
Revises: 0002_slack_webhook
Create Date: 2026-08-19

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003_domain_verifications"
down_revision: Union[str, None] = "0002_slack_webhook"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Declared with create_type=False and created explicitly in upgrade(), so the
# column definition below does not make alembic emit a second CREATE TYPE.
domain_verification_status = postgresql.ENUM(
    "pending", "verified", "failed", name="domain_verification_status", create_type=False
)


def upgrade() -> None:
    bind = op.get_bind()
    domain_verification_status.create(bind, checkfirst=True)

    op.create_table(
        "domain_verifications",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organisations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # SET NULL rather than CASCADE: deleting the admin who added a domain must
        # not silently revoke the organisation's scanning authority for it.
        sa.Column(
            "created_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("domain", sa.String(253), nullable=False),
        sa.Column("token", sa.String(64), nullable=False),
        sa.Column("token_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "status", domain_verification_status, nullable=False, server_default="pending"
        ),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        # Per organisation, not global. Two unrelated companies can legitimately
        # both claim the same domain — an agency and its client, say — and each
        # must prove control independently. A TXT RRset holds several strings, so
        # both tokens can be published side by side.
        sa.UniqueConstraint("org_id", "domain", name="uq_domain_verifications_org_domain"),
    )
    op.create_index("ix_domain_verifications_org_id", "domain_verifications", ["org_id"])
    op.create_index("ix_domain_verifications_domain", "domain_verifications", ["domain"])


def downgrade() -> None:
    # Discards every challenge token. Organisations keep whatever is already in
    # organisations.verified_domains, so nobody loses scanning access on the way
    # down; re-upgrading means re-adding and re-verifying any domain that had not
    # yet been granted.
    op.drop_table("domain_verifications")

    bind = op.get_bind()
    domain_verification_status.drop(bind, checkfirst=True)
