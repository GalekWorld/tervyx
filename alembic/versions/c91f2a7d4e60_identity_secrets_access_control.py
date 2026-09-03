"""identity secrets access control

Revision ID: c91f2a7d4e60
Revises: b76d20e732f1
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "c91f2a7d4e60"
down_revision: str | None = "b76d20e732f1"
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
        "identity_providers",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("provider_type", sa.String(50), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("issuer", sa.String(2048), nullable=False),
        sa.Column("client_id", sa.String(255), nullable=False),
        sa.Column("client_secret_reference", sa.String(500), nullable=False),
        sa.Column("scopes", sa.JSON(), nullable=False),
        sa.Column("allowed_redirect_uris", sa.JSON(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("enforce_mfa", sa.Boolean(), nullable=False),
        sa.Column("provider_tenant_id", sa.String(255), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "provider_type IN ('entra', 'okta', 'google', 'keycloak', 'generic')",
            name="ck_identity_provider_type",
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "name"),
    )
    op.create_index(
        "ix_identity_providers_organization_id", "identity_providers", ["organization_id"]
    )
    op.create_index(
        "ix_identity_providers_org_enabled",
        "identity_providers",
        ["organization_id", "enabled"],
    )

    op.create_table(
        "federated_identities",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("provider_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("subject", sa.String(500), nullable=False),
        sa.Column("provider_tenant_id", sa.String(255), nullable=True),
        sa.Column("email", sa.String(320), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["provider_id"], ["identity_providers.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "provider_id", "subject"),
        sa.UniqueConstraint("organization_id", "provider_id", "user_id"),
    )
    op.create_index(
        "ix_federated_identities_organization_id", "federated_identities", ["organization_id"]
    )
    op.create_index("ix_federated_identities_provider_id", "federated_identities", ["provider_id"])
    op.create_index("ix_federated_identities_user_id", "federated_identities", ["user_id"])

    op.create_table(
        "auth_sessions",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("provider_id", sa.Uuid(), nullable=True),
        sa.Column("auth_method", sa.String(50), nullable=False),
        sa.Column("mfa_verified", sa.Boolean(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason", sa.String(500), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["provider_id"], ["identity_providers.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_auth_sessions_organization_id", "auth_sessions", ["organization_id"])
    op.create_index("ix_auth_sessions_provider_id", "auth_sessions", ["provider_id"])
    op.create_index("ix_auth_sessions_user_id", "auth_sessions", ["user_id"])
    op.create_index("ix_auth_sessions_org_user", "auth_sessions", ["organization_id", "user_id"])

    op.create_table(
        "oidc_login_transactions",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("provider_id", sa.Uuid(), nullable=False),
        sa.Column("state_hash", sa.String(64), nullable=False),
        sa.Column("nonce", sa.String(255), nullable=False),
        sa.Column("code_verifier_ciphertext", sa.Text(), nullable=False),
        sa.Column("redirect_uri", sa.String(2048), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["provider_id"], ["identity_providers.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("state_hash"),
    )
    op.create_index(
        "ix_oidc_login_transactions_organization_id",
        "oidc_login_transactions",
        ["organization_id"],
    )
    op.create_index(
        "ix_oidc_login_transactions_provider_id", "oidc_login_transactions", ["provider_id"]
    )

    op.create_table(
        "user_capabilities",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("capability", sa.String(100), nullable=False),
        sa.Column("effect", sa.String(10), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("effect IN ('allow', 'deny')", name="ck_user_capability_effect"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "user_id", "capability"),
    )
    op.create_index(
        "ix_user_capabilities_organization_id", "user_capabilities", ["organization_id"]
    )
    op.create_index("ix_user_capabilities_user_id", "user_capabilities", ["user_id"])

    op.add_column("refresh_tokens", sa.Column("session_id", sa.Uuid(), nullable=True))
    op.create_foreign_key(
        "fk_refresh_tokens_session_id",
        "refresh_tokens",
        "auth_sessions",
        ["session_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_index("ix_refresh_tokens_session_id", "refresh_tokens", ["session_id"])

    if op.get_bind().dialect.name == "postgresql":
        for table in (
            "identity_providers",
            "federated_identities",
            "auth_sessions",
            "oidc_login_transactions",
            "user_capabilities",
        ):
            _tenant_policy(table)


def downgrade() -> None:
    op.drop_index("ix_refresh_tokens_session_id", table_name="refresh_tokens")
    op.drop_constraint("fk_refresh_tokens_session_id", "refresh_tokens", type_="foreignkey")
    op.drop_column("refresh_tokens", "session_id")
    op.drop_table("user_capabilities")
    op.drop_table("oidc_login_transactions")
    op.drop_table("auth_sessions")
    op.drop_table("federated_identities")
    op.drop_table("identity_providers")
