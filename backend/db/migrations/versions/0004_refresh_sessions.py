"""refresh-token session families

Adds ``refresh_sessions``: one row per issued refresh token, keyed by the
token's SHA-256 hash, grouped into rotation families.

Before this table a refresh token was a bare JWT: valid until its exp claim,
with no way to revoke a session, no way to detect that a rotated token had
been replayed, and no way to sign a user out of a device. The rows here are
what make single-use rotation with family-wide reuse detection possible — see
models.refresh_session for the threat model.

No data migration on existing tokens: any refresh token issued before this
change has no row and is rejected with "Invalid refresh token" on its next
use, which forces a re-login exactly once. That is the correct behaviour —
a token that predates the control should not silently keep working outside it.

Revision ID: 0004_refresh_sessions
Revises: 0003_domain_verifications
Create Date: 2026-09-07

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004_refresh_sessions"
down_revision: Union[str, None] = "0003_domain_verifications"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "refresh_sessions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organisations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # SHA-256 hex of the refresh token. Never the token itself.
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("family_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "replaced_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("refresh_sessions.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.UniqueConstraint("token_hash", name="uq_refresh_sessions_token_hash"),
    )
    op.create_index("ix_refresh_sessions_user_id", "refresh_sessions", ["user_id"])
    op.create_index("ix_refresh_sessions_org_id", "refresh_sessions", ["org_id"])
    op.create_index("ix_refresh_sessions_family_id", "refresh_sessions", ["family_id"])


def downgrade() -> None:
    op.drop_table("refresh_sessions")
