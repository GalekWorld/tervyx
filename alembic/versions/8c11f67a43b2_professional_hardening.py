"""professional hardening

Revision ID: 8c11f67a43b2
Revises: 5bdba41590e5
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "8c11f67a43b2"
down_revision: str | None = "5bdba41590e5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TENANT_TABLES = [
    "users",
    "endpoints",
    "security_events",
    "alerts",
    "incidents",
    "investigations",
    "audit_logs",
    "integration_accounts",
    "integration_checkpoints",
    "dead_letter_events",
]


def upgrade() -> None:
    op.add_column("users", sa.Column("password_hash", sa.String(length=500), nullable=True))
    op.add_column(
        "users", sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true())
    )
    if op.get_bind().dialect.name != "postgresql":
        return
    tenant = "NULLIF(current_setting('app.current_organization_id', true), '')::uuid"
    for table in TENANT_TABLES:
        op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
        op.execute(
            f'CREATE POLICY tenant_isolation ON "{table}" FOR ALL '
            f"USING (organization_id = {tenant}) WITH CHECK (organization_id = {tenant})"
        )
    op.execute("ALTER TABLE alert_security_events ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE alert_security_events FORCE ROW LEVEL SECURITY")
    op.execute(f"""CREATE POLICY tenant_isolation ON alert_security_events FOR ALL USING (
        EXISTS (SELECT 1 FROM alerts a WHERE a.id = alert_id AND a.organization_id = {tenant})
    ) WITH CHECK (
        EXISTS (SELECT 1 FROM alerts a WHERE a.id = alert_id AND a.organization_id = {tenant})
    )""")
    op.execute("ALTER TABLE incident_alerts ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE incident_alerts FORCE ROW LEVEL SECURITY")
    op.execute(f"""CREATE POLICY tenant_isolation ON incident_alerts FOR ALL USING (
        EXISTS (SELECT 1 FROM incidents i WHERE i.id = incident_id AND i.organization_id = {tenant})
    ) WITH CHECK (
        EXISTS (SELECT 1 FROM incidents i WHERE i.id = incident_id AND i.organization_id = {tenant})
    )""")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        for table in ["alert_security_events", "incident_alerts", *TENANT_TABLES]:
            op.execute(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"')
            op.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')
    op.drop_column("users", "is_active")
    op.drop_column("users", "password_hash")
