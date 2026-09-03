"""investigation engine fields and incident idempotency

Revision ID: f4b_investigation_engine
Revises: f4a1_migration_indexes
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "f4b_investigation_engine"
down_revision: str | None = "f4a1_migration_indexes"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "investigations",
        sa.Column("timeline", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
    )
    op.alter_column("investigations", "timeline", server_default=None)
    op.create_check_constraint(
        "ck_investigation_status",
        "investigations",
        "status IN ('pending', 'in_progress', 'completed', 'closed')",
    )
    op.create_unique_constraint(
        "uq_investigations_organization_incident",
        "investigations",
        ["organization_id", "incident_id"],
    )


def downgrade() -> None:
    op.drop_constraint("uq_investigations_organization_incident", "investigations", type_="unique")
    op.drop_constraint("ck_investigation_status", "investigations", type_="check")
    op.drop_column("investigations", "timeline")
