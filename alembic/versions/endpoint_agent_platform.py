"""add tenant-safe endpoint agent identity and heartbeat state"""

from alembic import op
import sqlalchemy as sa

revision = "endpoint_agent_platform"
down_revision = "pam_jit_platform_admin"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("endpoints", sa.Column("identity_key", sa.String(128), nullable=True))
    op.execute("UPDATE endpoints SET identity_key = md5(id::text) WHERE identity_key IS NULL")
    op.alter_column("endpoints", "identity_key", nullable=False)
    op.create_unique_constraint("uq_endpoints_identity_key", "endpoints", ["identity_key"])
    op.add_column("endpoints", sa.Column("enrollment_token_hash", sa.String(64), nullable=True))
    op.create_unique_constraint("uq_endpoints_enrollment_token_hash", "endpoints", ["enrollment_token_hash"])
    op.add_column("endpoints", sa.Column("enrolled_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("endpoints", sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("endpoints", sa.Column("certificate_serial", sa.String(255), nullable=True))
    op.add_column("endpoints", sa.Column("certificate_expires_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("endpoints", sa.Column("heartbeat_interval_seconds", sa.Integer(), nullable=False, server_default="60"))
    op.add_column("endpoints", sa.Column("last_health", sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")))
    op.add_column("endpoints", sa.Column("agent_version", sa.String(100), nullable=True))


def downgrade() -> None:
    for name in ("uq_endpoints_enrollment_token_hash", "uq_endpoints_identity_key"):
        op.drop_constraint(name, "endpoints", type_="unique")
    for name in ("agent_version", "last_health", "heartbeat_interval_seconds", "certificate_expires_at", "certificate_serial", "revoked_at", "enrolled_at", "enrollment_token_hash", "identity_key"):
        op.drop_column("endpoints", name)
