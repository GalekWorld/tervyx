"""add append-only tamper-evident audit ledger

Revision ID: audit_ledger_strong_sink
Revises: self_monitoring_signals
"""

from alembic import op
import sqlalchemy as sa

revision = "audit_ledger_strong_sink"
down_revision = "self_monitoring_signals"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "audit_ledger_entries",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("entry_type", sa.String(length=50), nullable=False),
        sa.Column("audit_log_id", sa.Uuid(), nullable=True),
        sa.Column("security_signal_id", sa.Uuid(), nullable=True),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("previous_hash", sa.String(length=64), nullable=False),
        sa.Column("entry_hash", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["audit_log_id"], ["audit_logs.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["security_signal_id"], ["security_signals.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "sequence"),
        sa.UniqueConstraint("audit_log_id"),
        sa.UniqueConstraint("security_signal_id"),
    )
    op.create_index(
        "ix_audit_ledger_entries_organization_id", "audit_ledger_entries", ["organization_id"]
    )
    op.create_index(
        "ix_audit_ledger_org_sequence",
        "audit_ledger_entries",
        ["organization_id", "sequence"],
    )
    if op.get_bind().dialect.name != "postgresql":
        return
    tenant = "NULLIF(current_setting('app.current_organization_id', true), '')::uuid"
    op.execute('ALTER TABLE "audit_ledger_entries" ENABLE ROW LEVEL SECURITY')
    op.execute('ALTER TABLE "audit_ledger_entries" FORCE ROW LEVEL SECURITY')
    op.execute(
        f"CREATE POLICY tenant_isolation ON audit_ledger_entries FOR ALL "
        f"USING (organization_id = {tenant}) WITH CHECK (organization_id = {tenant})"
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION prevent_audit_ledger_mutation() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'audit ledger is append-only';
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_ledger_no_update
        BEFORE UPDATE OR DELETE ON audit_ledger_entries
        FOR EACH ROW EXECUTE FUNCTION prevent_audit_ledger_mutation()
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION prevent_audit_log_mutation() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'audit log is append-only once the ledger is enabled';
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_log_no_update
        BEFORE UPDATE OR DELETE ON audit_logs
        FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_mutation()
        """
    )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP POLICY IF EXISTS tenant_isolation ON audit_ledger_entries")
        op.execute('ALTER TABLE "audit_ledger_entries" DISABLE ROW LEVEL SECURITY')
    op.execute("DROP TRIGGER IF EXISTS audit_ledger_no_update ON audit_ledger_entries")
    op.execute("DROP FUNCTION IF EXISTS prevent_audit_ledger_mutation()")
    op.execute("DROP TRIGGER IF EXISTS audit_log_no_update ON audit_logs")
    op.execute("DROP FUNCTION IF EXISTS prevent_audit_log_mutation()")
    op.drop_index("ix_audit_ledger_org_sequence", table_name="audit_ledger_entries")
    op.drop_index("ix_audit_ledger_entries_organization_id", table_name="audit_ledger_entries")
    op.drop_table("audit_ledger_entries")
