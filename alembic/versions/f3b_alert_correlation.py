"""alert correlation groups

Revision ID: f3b_alert_correlation
Revises: f3a5_detection_rule_operations
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "f3b_alert_correlation"
down_revision: str | None = "f3a5_detection_rule_operations"
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
        "alert_groups",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("correlation_key", sa.String(length=512), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("severity", sa.Integer(), nullable=False),
        sa.Column("affected_endpoint_ids", sa.JSON(), nullable=False),
        sa.Column("affected_users", sa.JSON(), nullable=False),
        sa.Column("source_ips", sa.JSON(), nullable=False),
        sa.Column("destination_ips", sa.JSON(), nullable=False),
        sa.Column("mitre_attack", sa.JSON(), nullable=False),
        sa.Column("evidence_summary", sa.JSON(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("severity >= 0 AND severity <= 10", name="ck_alert_group_severity"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_alert_groups_org_last_seen",
        "alert_groups",
        ["organization_id", sa.text("last_seen DESC")],
    )
    op.create_index(
        "ix_alert_groups_org_correlation", "alert_groups", ["organization_id", "correlation_key"]
    )
    op.create_table(
        "alert_group_alerts",
        sa.Column("alert_group_id", sa.Uuid(), nullable=False),
        sa.Column("alert_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(["alert_group_id"], ["alert_groups.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["alert_id"], ["alerts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("alert_group_id", "alert_id"),
        sa.UniqueConstraint("alert_id"),
    )
    op.create_index("ix_alert_group_alerts_alert_id", "alert_group_alerts", ["alert_id"])
    if op.get_bind().dialect.name == "postgresql":
        _tenant_policy("alert_groups")
        tenant = "NULLIF(current_setting('app.current_organization_id', true), '')::uuid"
        op.execute('ALTER TABLE "alert_group_alerts" ENABLE ROW LEVEL SECURITY')
        op.execute('ALTER TABLE "alert_group_alerts" FORCE ROW LEVEL SECURITY')
        op.execute(
            "CREATE POLICY tenant_isolation ON alert_group_alerts FOR ALL USING ("
            f"EXISTS (SELECT 1 FROM alert_groups g WHERE g.id = alert_group_id AND g.organization_id = {tenant})"
            f" AND EXISTS (SELECT 1 FROM alerts a WHERE a.id = alert_id AND a.organization_id = {tenant})"
            ") WITH CHECK ("
            f"EXISTS (SELECT 1 FROM alert_groups g WHERE g.id = alert_group_id AND g.organization_id = {tenant})"
            f" AND EXISTS (SELECT 1 FROM alerts a WHERE a.id = alert_id AND a.organization_id = {tenant})"
            ")"
        )


def downgrade() -> None:
    op.drop_table("alert_group_alerts")
    op.drop_table("alert_groups")
