"""hardening B detection traceability and asset criticality

Revision ID: hb_hardening_detection
Revises: h4a_tenant_referential_integrity
"""
from collections.abc import Sequence
from alembic import op
import sqlalchemy as sa

revision: str = "hb_hardening_detection"
down_revision: str | None = "h4a_tenant_referential_integrity"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("endpoints", sa.Column("criticality", sa.Integer(), nullable=False, server_default="3"))
    op.create_check_constraint("ck_endpoint_criticality", "endpoints", "criticality BETWEEN 1 AND 5")
    op.alter_column("endpoints", "criticality", server_default=None)
    op.create_check_constraint("ck_incident_sla_due_after_first_seen", "incidents", "sla_due_at >= first_seen")


def downgrade() -> None:
    op.drop_constraint("ck_incident_sla_due_after_first_seen", "incidents", type_="check")
    op.drop_constraint("ck_endpoint_criticality", "endpoints", type_="check")
    op.drop_column("endpoints", "criticality")
