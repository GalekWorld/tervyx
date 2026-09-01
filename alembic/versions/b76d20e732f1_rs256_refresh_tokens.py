"""rs256 refresh tokens

Revision ID: b76d20e732f1
Revises: 8c11f67a43b2
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "b76d20e732f1"
down_revision: Union[str, None] = "8c11f67a43b2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "refresh_tokens",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("replaced_by_id", sa.Uuid(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["replaced_by_id"], ["refresh_tokens.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index(
        "ix_refresh_tokens_organization_id", "refresh_tokens", ["organization_id"]
    )
    op.create_index("ix_refresh_tokens_user_id", "refresh_tokens", ["user_id"])
    op.create_index(
        "ix_refresh_tokens_org_user", "refresh_tokens", ["organization_id", "user_id"]
    )
    if op.get_bind().dialect.name == "postgresql":
        tenant = "NULLIF(current_setting('app.current_organization_id', true), '')::uuid"
        op.execute("ALTER TABLE refresh_tokens ENABLE ROW LEVEL SECURITY")
        op.execute("ALTER TABLE refresh_tokens FORCE ROW LEVEL SECURITY")
        op.execute(
            "CREATE POLICY tenant_isolation ON refresh_tokens FOR ALL "
            f"USING (organization_id = {tenant}) WITH CHECK (organization_id = {tenant})"
        )


def downgrade() -> None:
    op.drop_index("ix_refresh_tokens_org_user", table_name="refresh_tokens")
    op.drop_index("ix_refresh_tokens_user_id", table_name="refresh_tokens")
    op.drop_index("ix_refresh_tokens_organization_id", table_name="refresh_tokens")
    op.drop_table("refresh_tokens")
