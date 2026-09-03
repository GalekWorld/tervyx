"""add deterministic self-monitoring security signals

Revision ID: self_monitoring_signals
Revises: m_asvs_integration_org_fks
"""

from alembic import op
import sqlalchemy as sa

revision = "self_monitoring_signals"
down_revision = "m_asvs_integration_org_fks"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "security_signals",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("signal_type", sa.String(length=100), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("fingerprint", sa.String(length=128), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("source_action", sa.String(length=255), nullable=False),
        sa.Column("actor_id", sa.String(length=255), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("occurrences", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "fingerprint"),
        sa.CheckConstraint(
            "severity IN ('low', 'medium', 'high', 'critical')",
            name="ck_security_signal_severity",
        ),
        sa.CheckConstraint(
            "status IN ('open', 'acknowledged', 'closed')",
            name="ck_security_signal_status",
        ),
    )
    op.create_index(
        "ix_security_signals_organization_id", "security_signals", ["organization_id"]
    )
    op.create_index(
        "ix_security_signals_org_last_seen",
        "security_signals",
        ["organization_id", "last_seen_at"],
    )
    if op.get_bind().dialect.name == "postgresql":
        tenant = "NULLIF(current_setting('app.current_organization_id', true), '')::uuid"
        op.execute('ALTER TABLE "security_signals" ENABLE ROW LEVEL SECURITY')
        op.execute('ALTER TABLE "security_signals" FORCE ROW LEVEL SECURITY')
        op.execute(
            f"CREATE POLICY tenant_isolation ON security_signals FOR ALL "
            f"USING (organization_id = {tenant}) WITH CHECK (organization_id = {tenant})"
        )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP POLICY IF EXISTS tenant_isolation ON security_signals")
        op.execute('ALTER TABLE "security_signals" DISABLE ROW LEVEL SECURITY')
    op.drop_index("ix_security_signals_org_last_seen", table_name="security_signals")
    op.drop_index("ix_security_signals_organization_id", table_name="security_signals")
    op.drop_table("security_signals")
