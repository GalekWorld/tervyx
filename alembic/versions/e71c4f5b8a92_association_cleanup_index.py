"""association cleanup index

Revision ID: e71c4f5b8a92
Revises: d24b7e91f3a4
"""

from collections.abc import Sequence

from alembic import op

revision: str = "e71c4f5b8a92"
down_revision: str | None = "d24b7e91f3a4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_alert_security_events_security_event_id "
        "ON alert_security_events (security_event_id)"
    )


def downgrade() -> None:
    op.drop_index("ix_alert_security_events_security_event_id", table_name="alert_security_events")
