"""initial schema

Creates the seven core tables plus their enums and indexes.

Revision ID: 0001_initial
Revises:
Create Date: 2026-08-03

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Enum types are created explicitly so the table definitions below can reuse
# them without alembic emitting duplicate CREATE TYPE statements.
user_role = postgresql.ENUM(
    "owner", "admin", "analyst", "viewer", name="user_role", create_type=False
)
asset_status = postgresql.ENUM(
    "active", "inactive", "new", "changed", "decommissioned",
    name="asset_status", create_type=False,
)
scan_status = postgresql.ENUM(
    "queued", "running", "completed", "failed", "cancelled",
    name="scan_status", create_type=False,
)
severity = postgresql.ENUM(
    "info", "low", "medium", "high", "critical", name="severity", create_type=False
)
finding_status = postgresql.ENUM(
    "open", "triaged", "confirmed", "remediated", "false_positive", "accepted_risk",
    name="finding_status", create_type=False,
)
log_level = postgresql.ENUM(
    "debug", "info", "warning", "error", name="log_level", create_type=False
)


def upgrade() -> None:
    bind = op.get_bind()

    for enum in (user_role, asset_status, scan_status, severity, finding_status, log_level):
        enum.create(bind, checkfirst=True)

    # --- organisations -----------------------------------------------------
    op.create_table(
        "organisations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("domain", sa.String(253), nullable=False),
        sa.Column(
            "verified_domains",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="[]",
        ),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )
    op.create_index("ix_organisations_domain", "organisations", ["domain"])

    # --- users -------------------------------------------------------------
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organisations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("full_name", sa.String(255), nullable=True),
        sa.Column("role", user_role, nullable=False, server_default="analyst"),
        sa.Column("password_hash", sa.String(128), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("token_version", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.UniqueConstraint("org_id", "email", name="uq_users_org_email"),
    )
    op.create_index("ix_users_org_id", "users", ["org_id"])
    op.create_index("ix_users_email", "users", ["email"])

    # --- assets ------------------------------------------------------------
    op.create_table(
        "assets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organisations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("hostname", sa.String(253), nullable=False),
        sa.Column("ip", sa.String(45), nullable=True),
        sa.Column(
            "ports", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="[]"
        ),
        sa.Column(
            "tech_stack",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="[]",
        ),
        sa.Column("risk_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("last_scanned", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", asset_status, nullable=False, server_default="new"),
        sa.Column("discovery_source", sa.String(64), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.UniqueConstraint("org_id", "hostname", name="uq_assets_org_hostname"),
    )
    op.create_index("ix_assets_org_id", "assets", ["org_id"])
    op.create_index("ix_assets_hostname", "assets", ["hostname"])
    op.create_index("ix_assets_ip", "assets", ["ip"])
    op.create_index("ix_assets_org_risk", "assets", ["org_id", "risk_score"])
    op.create_index("ix_assets_org_status", "assets", ["org_id", "status"])
    op.create_index("ix_assets_ports_gin", "assets", ["ports"], postgresql_using="gin")
    op.create_index("ix_assets_tech_gin", "assets", ["tech_stack"], postgresql_using="gin")

    # --- scans -------------------------------------------------------------
    op.create_table(
        "scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organisations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "created_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("target", sa.String(253), nullable=False),
        sa.Column("status", scan_status, nullable=False, server_default="queued"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "config", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="{}"
        ),
        sa.Column("current_stage", sa.String(64), nullable=True),
        sa.Column("progress", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("assets_discovered", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("findings_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("celery_task_id", sa.String(155), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )
    op.create_index("ix_scans_org_id", "scans", ["org_id"])
    op.create_index("ix_scans_target", "scans", ["target"])
    op.create_index("ix_scans_celery_task_id", "scans", ["celery_task_id"])
    op.create_index("ix_scans_org_started", "scans", ["org_id", "started_at"])
    op.create_index("ix_scans_org_status", "scans", ["org_id", "status"])

    # --- findings ----------------------------------------------------------
    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organisations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "asset_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("cve_id", sa.String(32), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cvss_vector", sa.String(128), nullable=True),
        sa.Column("severity", severity, nullable=False, server_default="info"),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("status", finding_status, nullable=False, server_default="open"),
        sa.Column("source", sa.String(64), nullable=True),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column(
            "evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="{}"
        ),
        sa.Column(
            "references",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="[]",
        ),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        # Makes re-scans idempotent: the workers ON CONFLICT against this.
        sa.UniqueConstraint("org_id", "fingerprint", name="uq_findings_org_fingerprint"),
    )
    op.create_index("ix_findings_org_id", "findings", ["org_id"])
    op.create_index("ix_findings_asset_id", "findings", ["asset_id"])
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"])
    op.create_index("ix_findings_cve_id", "findings", ["cve_id"])
    op.create_index("ix_findings_org_severity", "findings", ["org_id", "severity"])
    op.create_index("ix_findings_org_status", "findings", ["org_id", "status"])
    op.create_index("ix_findings_org_cve", "findings", ["org_id", "cve_id"])

    # --- scan_logs ---------------------------------------------------------
    op.create_table(
        "scan_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("level", log_level, nullable=False, server_default="info"),
        sa.Column("stage", sa.String(64), nullable=True),
    )
    op.create_index("ix_scan_logs_scan_id", "scan_logs", ["scan_id"])
    op.create_index("ix_scan_logs_scan_ts", "scan_logs", ["scan_id", "timestamp"])

    # --- reports -----------------------------------------------------------
    op.create_table(
        "reports",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "org_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organisations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "generated_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("file_path", sa.String(1024), nullable=False),
        sa.Column("title", sa.String(255), nullable=True),
        sa.Column("format", sa.String(16), nullable=False, server_default="pdf"),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.Column(
            "summary", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="{}"
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )
    op.create_index("ix_reports_org_id", "reports", ["org_id"])
    op.create_index("ix_reports_org_generated", "reports", ["org_id", "generated_at"])


def downgrade() -> None:
    op.drop_table("reports")
    op.drop_table("scan_logs")
    op.drop_table("findings")
    op.drop_table("scans")
    op.drop_table("assets")
    op.drop_table("users")
    op.drop_table("organisations")

    bind = op.get_bind()
    for enum in (log_level, finding_status, severity, scan_status, asset_status, user_role):
        enum.drop(bind, checkfirst=True)
