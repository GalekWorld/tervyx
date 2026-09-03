"""incident lifecycle

Revision ID: f3c5_incident_lifecycle
Revises: f3c_incident_engine
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "f3c5_incident_lifecycle"
down_revision: str | None = "f3c_incident_engine"
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
    op.add_column("incidents", sa.Column("assigned_to", sa.Uuid(), nullable=True))
    op.add_column("incidents", sa.Column("resolution", sa.Text(), nullable=True))
    op.add_column("incidents", sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("incidents", sa.Column("sla_due_at", sa.DateTime(timezone=True), nullable=True))
    if op.get_bind().dialect.name == "postgresql":
        op.execute("UPDATE incidents SET sla_due_at = first_seen + interval '24 hours'")
    else:
        op.execute("UPDATE incidents SET sla_due_at = first_seen")
    op.alter_column("incidents", "sla_due_at", nullable=False)
    op.create_check_constraint(
        "ck_incident_status",
        "incidents",
        "status IN ('open', 'investigating', 'contained', 'resolved', 'false_positive', 'reopened')",
    )
    op.create_foreign_key(
        "fk_incidents_assigned_to",
        "incidents",
        "users",
        ["assigned_to"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_incidents_assigned_to", "incidents", ["assigned_to"])
    op.create_table(
        "incident_history",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("actor_id", sa.Uuid(), nullable=True),
        sa.Column("action", sa.String(length=50), nullable=False),
        sa.Column("previous_status", sa.String(length=50), nullable=True),
        sa.Column("new_status", sa.String(length=50), nullable=True),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["actor_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_incident_history_org_incident", "incident_history", ["organization_id", "incident_id"]
    )
    if op.get_bind().dialect.name == "postgresql":
        _tenant_policy("incident_history")


def downgrade() -> None:
    op.drop_table("incident_history")
    op.drop_index("ix_incidents_assigned_to", table_name="incidents")
    op.drop_constraint("fk_incidents_assigned_to", "incidents", type_="foreignkey")
    op.drop_constraint("ck_incident_status", "incidents", type_="check")
    op.drop_column("incidents", "sla_due_at")
    op.drop_column("incidents", "closed_at")
    op.drop_column("incidents", "resolution")
    op.drop_column("incidents", "assigned_to")
