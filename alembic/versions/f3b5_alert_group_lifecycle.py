"""alert group lifecycle

Revision ID: f3b5_alert_group_lifecycle
Revises: f3b_alert_correlation
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "f3b5_alert_group_lifecycle"
down_revision: str | None = "f3b_alert_correlation"
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
    op.add_column(
        "alert_groups",
        sa.Column("status", sa.String(length=50), nullable=False, server_default="open"),
    )
    op.add_column("alert_groups", sa.Column("assigned_to", sa.Uuid(), nullable=True))
    op.add_column("alert_groups", sa.Column("resolution_reason", sa.Text(), nullable=True))
    op.add_column("alert_groups", sa.Column("analyst_feedback", sa.Text(), nullable=True))
    op.add_column("alert_groups", sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True))
    op.create_check_constraint(
        "ck_alert_group_status",
        "alert_groups",
        "status IN ('open', 'investigating', 'resolved', 'false_positive')",
    )
    op.create_foreign_key(
        "fk_alert_groups_assigned_to",
        "alert_groups",
        "users",
        ["assigned_to"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_alert_groups_assigned_to", "alert_groups", ["assigned_to"])
    op.alter_column("alert_groups", "status", server_default=None)
    op.create_table(
        "alert_group_history",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("alert_group_id", sa.Uuid(), nullable=False),
        sa.Column("actor_id", sa.Uuid(), nullable=True),
        sa.Column("action", sa.String(length=50), nullable=False),
        sa.Column("previous_status", sa.String(length=50), nullable=True),
        sa.Column("new_status", sa.String(length=50), nullable=True),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["alert_group_id"], ["alert_groups.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["actor_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_alert_group_history_org_group",
        "alert_group_history",
        ["organization_id", "alert_group_id"],
    )
    if op.get_bind().dialect.name == "postgresql":
        _tenant_policy("alert_group_history")


def downgrade() -> None:
    op.drop_table("alert_group_history")
    op.drop_index("ix_alert_groups_assigned_to", table_name="alert_groups")
    op.drop_constraint("fk_alert_groups_assigned_to", "alert_groups", type_="foreignkey")
    op.drop_constraint("ck_alert_group_status", "alert_groups", type_="check")
    op.drop_column("alert_groups", "closed_at")
    op.drop_column("alert_groups", "analyst_feedback")
    op.drop_column("alert_groups", "resolution_reason")
    op.drop_column("alert_groups", "assigned_to")
    op.drop_column("alert_groups", "status")
