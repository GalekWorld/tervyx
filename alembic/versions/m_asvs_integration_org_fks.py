"""restore direct organization integrity for integration child rows

Revision ID: m_asvs_integration_org_fks
Revises: m_asvs_tenant_integration_fks
"""
from collections.abc import Sequence
from alembic import op

revision: str = "m_asvs_integration_org_fks"
down_revision: str | None = "m_asvs_tenant_integration_fks"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_foreign_key(
        "dead_letter_events_organization_id_fkey",
        "dead_letter_events", "organizations", ["organization_id"], ["id"], ondelete="CASCADE"
    )
    op.create_foreign_key(
        "integration_checkpoints_organization_id_fkey",
        "integration_checkpoints", "organizations", ["organization_id"], ["id"], ondelete="CASCADE"
    )


def downgrade() -> None:
    op.drop_constraint("integration_checkpoints_organization_id_fkey", "integration_checkpoints", type_="foreignkey")
    op.drop_constraint("dead_letter_events_organization_id_fkey", "dead_letter_events", type_="foreignkey")
