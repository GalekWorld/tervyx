"""add tenant-scoped platform admin PAM/JIT

Revision ID: pam_jit_platform_admin
Revises: audit_ledger_strong_sink
"""

from alembic import op
import sqlalchemy as sa

revision = "pam_jit_platform_admin"
down_revision = "audit_ledger_strong_sink"
branch_labels = None
depends_on = None


def _rls(table: str) -> None:
    tenant = "NULLIF(current_setting('app.current_organization_id', true), '')::uuid"
    op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
    op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
    op.execute(
        f'CREATE POLICY tenant_isolation ON "{table}" FOR ALL '
        f"USING (organization_id = {tenant}) WITH CHECK (organization_id = {tenant})"
    )


def upgrade() -> None:
    op.add_column("auth_sessions", sa.Column("mfa_verified_at", sa.DateTime(timezone=True)))
    op.add_column(
        "auth_sessions", sa.Column("mfa_methods", sa.JSON(), nullable=False, server_default="[]")
    )
    op.create_table(
        "platform_admin_eligibilities",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "user_id"),
    )
    op.create_table(
        "privileged_access_policies",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("approval_required", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("break_glass_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("max_duration_minutes", sa.Integer(), nullable=False, server_default="60"),
        sa.Column("step_up_max_age_minutes", sa.Integer(), nullable=False, server_default="15"),
        sa.Column("allowed_mfa_methods", sa.JSON(), nullable=False, server_default='["fido2", "passkey", "hardware", "ngcmfa", "webauthn"]'),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id"),
    )
    op.create_table(
        "privileged_access_requests",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("requester_id", sa.Uuid(), nullable=False),
        sa.Column("approver_id", sa.Uuid()),
        sa.Column("purpose", sa.String(500), nullable=False),
        sa.Column("requested_capabilities", sa.JSON(), nullable=False),
        sa.Column("requested_duration_minutes", sa.Integer(), nullable=False),
        sa.Column("break_glass", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("status", sa.String(20), nullable=False, server_default="requested"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("status IN ('requested', 'approved', 'active', 'denied', 'revoked', 'expired')", name="ck_privileged_access_request_status"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["requester_id"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["approver_id"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_privileged_access_requests_org_status", "privileged_access_requests", ["organization_id", "status"])
    op.create_table(
        "privileged_sessions",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("base_session_id", sa.Uuid(), nullable=False),
        sa.Column("request_id", sa.Uuid(), nullable=False),
        sa.Column("capabilities", sa.JSON(), nullable=False),
        sa.Column("step_up_verified_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("revocation_reason", sa.String(500)),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("status IN ('active', 'revoked', 'expired')", name="ck_privileged_session_status"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["base_session_id"], ["auth_sessions.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["request_id"], ["privileged_access_requests.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("request_id"),
    )
    op.create_index("ix_privileged_sessions_org_user", "privileged_sessions", ["organization_id", "user_id"])
    if op.get_bind().dialect.name == "postgresql":
        for table in ("platform_admin_eligibilities", "privileged_access_policies", "privileged_access_requests", "privileged_sessions"):
            _rls(table)


def downgrade() -> None:
    op.drop_index("ix_privileged_sessions_org_user", table_name="privileged_sessions")
    op.drop_table("privileged_sessions")
    op.drop_index("ix_privileged_access_requests_org_status", table_name="privileged_access_requests")
    op.drop_table("privileged_access_requests")
    op.drop_table("privileged_access_policies")
    op.drop_table("platform_admin_eligibilities")
    op.drop_column("auth_sessions", "mfa_methods")
    op.drop_column("auth_sessions", "mfa_verified_at")
