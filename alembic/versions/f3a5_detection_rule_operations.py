"""versioned detection rule operations

Revision ID: f3a5_detection_rule_operations
Revises: f3a_security_event_detection
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "f3a5_detection_rule_operations"
down_revision: str | None = "f3a_security_event_detection"
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
    op.add_column("alerts", sa.Column("rule_version", sa.Integer(), nullable=True))
    op.add_column("alerts", sa.Column("correlation_key", sa.String(length=512), nullable=True))
    op.create_index(
        "ix_alerts_org_correlation_occurred",
        "alerts",
        ["organization_id", "correlation_key", "occurred_at"],
    )
    op.create_table(
        "detection_rule_configurations",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("rule_id", sa.String(length=100), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("suppression_window_seconds", sa.Integer(), nullable=False),
        sa.Column("configuration", sa.JSON(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("version >= 1", name="ck_detection_rule_config_version"),
        sa.CheckConstraint(
            "suppression_window_seconds >= 0", name="ck_detection_rule_config_suppression"
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "rule_id", "version"),
    )
    op.create_index(
        "ix_detection_rule_configs_org_rule_active",
        "detection_rule_configurations",
        ["organization_id", "rule_id", "active"],
    )
    op.create_table(
        "detection_rule_metrics",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("rule_id", sa.String(length=100), nullable=False),
        sa.Column("executions", sa.Integer(), nullable=False),
        sa.Column("matches", sa.Integer(), nullable=False),
        sa.Column("alerts_created", sa.Integer(), nullable=False),
        sa.Column("alerts_suppressed", sa.Integer(), nullable=False),
        sa.Column("last_match", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "rule_id"),
    )
    op.create_index(
        "ix_detection_rule_metrics_org_rule",
        "detection_rule_metrics",
        ["organization_id", "rule_id"],
    )
    op.create_table(
        "detection_suppressions",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("rule_id", sa.String(length=100), nullable=False),
        sa.Column("correlation_key", sa.String(length=512), nullable=False),
        sa.Column("last_alert_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("suppressed_count", sa.Integer(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "rule_id", "correlation_key"),
    )
    op.create_index(
        "ix_detection_suppressions_org_rule",
        "detection_suppressions",
        ["organization_id", "rule_id"],
    )
    if op.get_bind().dialect.name == "postgresql":
        for table in (
            "detection_rule_configurations",
            "detection_rule_metrics",
            "detection_suppressions",
        ):
            _tenant_policy(table)


def downgrade() -> None:
    op.drop_table("detection_suppressions")
    op.drop_table("detection_rule_metrics")
    op.drop_table("detection_rule_configurations")
    op.drop_index("ix_alerts_org_correlation_occurred", table_name="alerts")
    op.drop_column("alerts", "correlation_key")
    op.drop_column("alerts", "rule_version")
