"""enforce tenant ownership for integration checkpoints and DLQ rows

Revision ID: m_asvs_tenant_integration_fks
Revises: hb_hardening_detection
"""
from collections.abc import Sequence
from alembic import op

revision: str = "m_asvs_tenant_integration_fks"
down_revision: str | None = "hb_hardening_detection"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_unique_constraint(
        "uq_integrations_organization_id", "integration_accounts", ["organization_id", "id"]
    )
    op.drop_constraint(
        "dead_letter_events_integration_account_id_fkey", "dead_letter_events", type_="foreignkey"
    )
    op.drop_constraint(
        "dead_letter_events_organization_id_fkey", "dead_letter_events", type_="foreignkey"
    )
    op.create_foreign_key(
        "fk_dlq_tenant_integration",
        "dead_letter_events",
        "integration_accounts",
        ["organization_id", "integration_account_id"],
        ["organization_id", "id"],
        ondelete="CASCADE",
    )
    op.create_foreign_key(
        "dead_letter_events_organization_id_fkey",
        "dead_letter_events", "organizations", ["organization_id"], ["id"], ondelete="CASCADE"
    )
    op.drop_constraint(
        "integration_checkpoints_integration_account_id_fkey",
        "integration_checkpoints",
        type_="foreignkey",
    )
    op.drop_constraint(
        "integration_checkpoints_organization_id_fkey", "integration_checkpoints", type_="foreignkey"
    )
    op.create_foreign_key(
        "fk_checkpoints_tenant_integration",
        "integration_checkpoints",
        "integration_accounts",
        ["organization_id", "integration_account_id"],
        ["organization_id", "id"],
        ondelete="CASCADE",
    )
    op.create_foreign_key(
        "integration_checkpoints_organization_id_fkey",
        "integration_checkpoints", "organizations", ["organization_id"], ["id"], ondelete="CASCADE"
    )


def downgrade() -> None:
    op.drop_constraint("fk_checkpoints_tenant_integration", "integration_checkpoints", type_="foreignkey")
    op.create_foreign_key(
        "integration_checkpoints_integration_account_id_fkey",
        "integration_checkpoints", "integration_accounts", ["integration_account_id"], ["id"], ondelete="CASCADE"
    )
    op.create_foreign_key(
        "integration_checkpoints_organization_id_fkey",
        "integration_checkpoints", "organizations", ["organization_id"], ["id"], ondelete="CASCADE"
    )
    op.drop_constraint("fk_dlq_tenant_integration", "dead_letter_events", type_="foreignkey")
    op.create_foreign_key(
        "dead_letter_events_integration_account_id_fkey",
        "dead_letter_events", "integration_accounts", ["integration_account_id"], ["id"], ondelete="CASCADE"
    )
    op.create_foreign_key(
        "dead_letter_events_organization_id_fkey",
        "dead_letter_events", "organizations", ["organization_id"], ["id"], ondelete="CASCADE"
    )
    op.drop_constraint("uq_integrations_organization_id", "integration_accounts", type_="unique")
