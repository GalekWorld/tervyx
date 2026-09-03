"""data performance resilience

Revision ID: d24b7e91f3a4
Revises: c91f2a7d4e60
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "d24b7e91f3a4"
down_revision: str | None = "c91f2a7d4e60"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _tenant_policy(table: str) -> None:
    tenant = "NULLIF(current_setting('app.current_organization_id', true), '')::uuid"
    op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
    op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
    op.execute(
        f'CREATE POLICY tenant_isolation ON "{table}" FOR ALL '
        f"USING (organization_id = {tenant}) WITH CHECK (organization_id = {tenant})"
    )


def upgrade() -> None:
    op.create_table(
        "tenant_quotas",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("max_events_per_day", sa.Integer(), nullable=False),
        sa.Column("max_jobs_per_minute", sa.Integer(), nullable=False),
        sa.Column("max_api_requests_per_minute", sa.Integer(), nullable=False),
        sa.Column("max_storage_bytes", sa.BigInteger(), nullable=False),
        sa.Column("max_queue_depth", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("max_events_per_day >= 0", name="ck_tenant_quota_events"),
        sa.CheckConstraint("max_jobs_per_minute >= 0", name="ck_tenant_quota_jobs"),
        sa.CheckConstraint("max_api_requests_per_minute >= 0", name="ck_tenant_quota_api"),
        sa.CheckConstraint("max_storage_bytes >= 0", name="ck_tenant_quota_storage"),
        sa.CheckConstraint("max_queue_depth >= 1", name="ck_tenant_quota_queue"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id"),
    )
    op.create_index("ix_tenant_quotas_organization_id", "tenant_quotas", ["organization_id"])
    op.create_table(
        "tenant_usage_ledgers",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("period_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("events_ingested", sa.Integer(), nullable=False),
        sa.Column("jobs_dispatched", sa.Integer(), nullable=False),
        sa.Column("hot_storage_bytes", sa.BigInteger(), nullable=False),
        sa.Column("archived_storage_bytes", sa.BigInteger(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "period_start"),
    )
    op.create_index(
        "ix_tenant_usage_ledgers_organization_id", "tenant_usage_ledgers", ["organization_id"]
    )
    op.create_index(
        "ix_tenant_usage_org_period", "tenant_usage_ledgers", ["organization_id", "period_start"]
    )
    op.create_table(
        "data_retention_policies",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("archive_after_days", sa.Integer(), nullable=False),
        sa.Column("retention_days", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("archive_after_days >= 1", name="ck_retention_archive_after_days"),
        sa.CheckConstraint("retention_days >= archive_after_days", name="ck_retention_days"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id"),
    )
    op.create_index(
        "ix_data_retention_policies_organization_id", "data_retention_policies", ["organization_id"]
    )
    op.create_table(
        "security_event_archives",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("storage_key", sa.String(2048), nullable=False),
        sa.Column("checksum_sha256", sa.String(64), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False),
        sa.Column("byte_count", sa.BigInteger(), nullable=False),
        sa.Column("first_occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(50), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "storage_key"),
    )
    op.create_index(
        "ix_security_event_archives_organization_id", "security_event_archives", ["organization_id"]
    )
    op.create_index(
        "ix_event_archives_org_range",
        "security_event_archives",
        ["organization_id", "first_occurred_at", "last_occurred_at"],
    )
    # Existing event tables retain foreign-key relationships; native partition conversion requires
    # an online table swap. These covering indexes are the safe first scaling step.
    op.create_index(
        "ix_events_org_endpoint_occurred",
        "security_events",
        ["organization_id", "endpoint_id", sa.text("occurred_at DESC")],
    )
    op.create_index(
        "ix_alerts_org_endpoint_occurred",
        "alerts",
        ["organization_id", "endpoint_id", sa.text("occurred_at DESC")],
    )
    if op.get_bind().dialect.name == "postgresql":
        for table in (
            "tenant_quotas",
            "tenant_usage_ledgers",
            "data_retention_policies",
            "security_event_archives",
        ):
            _tenant_policy(table)


def downgrade() -> None:
    op.drop_index("ix_alerts_org_endpoint_occurred", table_name="alerts")
    op.drop_index("ix_events_org_endpoint_occurred", table_name="security_events")
    op.drop_table("security_event_archives")
    op.drop_table("data_retention_policies")
    op.drop_table("tenant_usage_ledgers")
    op.drop_table("tenant_quotas")
