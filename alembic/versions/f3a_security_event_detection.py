"""security event normalization and deterministic detections

Revision ID: f3a_security_event_detection
Revises: e71c4f5b8a92
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "f3a_security_event_detection"
down_revision: str | None = "e71c4f5b8a92"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "security_events",
        sa.Column("normalized_data", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
    )
    op.add_column("alerts", sa.Column("rule_id", sa.String(length=100), nullable=True))
    op.add_column(
        "alerts",
        sa.Column("mitre_attack", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
    )
    op.add_column(
        "alerts", sa.Column("evidence", sa.JSON(), nullable=False, server_default=sa.text("'{}'"))
    )
    op.create_index("ix_alerts_rule_id", "alerts", ["rule_id"])
    op.alter_column("security_events", "normalized_data", server_default=None)
    op.alter_column("alerts", "mitre_attack", server_default=None)
    op.alter_column("alerts", "evidence", server_default=None)


def downgrade() -> None:
    op.drop_index("ix_alerts_rule_id", table_name="alerts")
    op.drop_column("alerts", "evidence")
    op.drop_column("alerts", "mitre_attack")
    op.drop_column("alerts", "rule_id")
    op.drop_column("security_events", "normalized_data")
