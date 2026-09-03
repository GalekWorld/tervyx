"""incident enrichment

Revision ID: f4a_incident_enrichment
Revises: f3c5_incident_lifecycle
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "f4a_incident_enrichment"
down_revision: str | None = "f3c5_incident_lifecycle"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "incident_enrichments",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("enrichment_type", sa.String(100), nullable=False),
        sa.Column("source_type", sa.String(20), nullable=False),
        sa.Column("source", sa.String(100), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "source_type IN ('internal', 'external')", name="ck_incident_enrichment_source"
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "incident_id", "fingerprint"),
    )
    op.create_index(
        "ix_incident_enrichments_org_incident",
        "incident_enrichments",
        ["organization_id", "incident_id"],
    )
    op.create_index(
        "ix_incident_enrichments_organization_id",
        "incident_enrichments",
        ["organization_id"],
    )
    op.create_index(
        "ix_incident_enrichments_incident_id",
        "incident_enrichments",
        ["incident_id"],
    )
    if op.get_bind().dialect.name == "postgresql":
        tenant = "NULLIF(current_setting('app.current_organization_id', true), '')::uuid"
        op.execute('ALTER TABLE "incident_enrichments" ENABLE ROW LEVEL SECURITY')
        op.execute('ALTER TABLE "incident_enrichments" FORCE ROW LEVEL SECURITY')
        op.execute(
            f"CREATE POLICY tenant_isolation ON incident_enrichments FOR ALL USING (organization_id = {tenant}) WITH CHECK (organization_id = {tenant})"
        )


def downgrade() -> None:
    op.drop_index("ix_incident_enrichments_incident_id", table_name="incident_enrichments")
    op.drop_index("ix_incident_enrichments_organization_id", table_name="incident_enrichments")
    op.drop_table("incident_enrichments")
