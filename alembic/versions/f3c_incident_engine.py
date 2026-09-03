"""incident engine

Revision ID: f3c_incident_engine
Revises: f3b5_alert_group_lifecycle
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "f3c_incident_engine"
down_revision: str | None = "f3b5_alert_group_lifecycle"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "incidents",
        sa.Column("priority", sa.String(length=20), nullable=False, server_default="medium"),
    )
    op.add_column(
        "incidents", sa.Column("confidence", sa.Float(), nullable=False, server_default="0.8")
    )
    op.add_column("incidents", sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True))
    op.add_column("incidents", sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True))
    op.add_column("incidents", sa.Column("correlation_key", sa.String(length=512), nullable=True))
    op.add_column(
        "incidents",
        sa.Column(
            "affected_endpoint_ids", sa.JSON(), nullable=False, server_default=sa.text("'[]'")
        ),
    )
    op.add_column(
        "incidents",
        sa.Column("affected_users", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
    )
    op.add_column(
        "incidents",
        sa.Column("source_ips", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
    )
    op.add_column(
        "incidents",
        sa.Column("destination_ips", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
    )
    op.add_column(
        "incidents",
        sa.Column("mitre_attack", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
    )
    op.add_column(
        "incidents",
        sa.Column("evidence", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
    )
    op.add_column(
        "incidents",
        sa.Column("timeline", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
    )
    op.execute("UPDATE incidents SET first_seen = occurred_at, last_seen = occurred_at")
    op.alter_column("incidents", "first_seen", nullable=False)
    op.alter_column("incidents", "last_seen", nullable=False)
    for column in (
        "priority",
        "confidence",
        "affected_endpoint_ids",
        "affected_users",
        "source_ips",
        "destination_ips",
        "mitre_attack",
        "evidence",
        "timeline",
    ):
        op.alter_column("incidents", column, server_default=None)
    op.create_index("ix_incidents_correlation_key", "incidents", ["correlation_key"])
    op.create_table(
        "incident_alert_groups",
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("alert_group_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["alert_group_id"], ["alert_groups.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("incident_id", "alert_group_id"),
        sa.UniqueConstraint("alert_group_id"),
    )
    op.create_index(
        "ix_incident_alert_groups_alert_group_id", "incident_alert_groups", ["alert_group_id"]
    )
    if op.get_bind().dialect.name == "postgresql":
        tenant = "NULLIF(current_setting('app.current_organization_id', true), '')::uuid"
        op.execute('ALTER TABLE "incident_alert_groups" ENABLE ROW LEVEL SECURITY')
        op.execute('ALTER TABLE "incident_alert_groups" FORCE ROW LEVEL SECURITY')
        op.execute(
            "CREATE POLICY tenant_isolation ON incident_alert_groups FOR ALL USING ("
            f"EXISTS (SELECT 1 FROM incidents i WHERE i.id = incident_id AND i.organization_id = {tenant})"
            f" AND EXISTS (SELECT 1 FROM alert_groups g WHERE g.id = alert_group_id AND g.organization_id = {tenant})"
            ") WITH CHECK ("
            f"EXISTS (SELECT 1 FROM incidents i WHERE i.id = incident_id AND i.organization_id = {tenant})"
            f" AND EXISTS (SELECT 1 FROM alert_groups g WHERE g.id = alert_group_id AND g.organization_id = {tenant})"
            ")"
        )


def downgrade() -> None:
    op.drop_table("incident_alert_groups")
    op.drop_index("ix_incidents_correlation_key", table_name="incidents")
    for column in (
        "timeline",
        "evidence",
        "mitre_attack",
        "destination_ips",
        "source_ips",
        "affected_users",
        "affected_endpoint_ids",
        "correlation_key",
        "last_seen",
        "first_seen",
        "confidence",
        "priority",
    ):
        op.drop_column("incidents", column)
