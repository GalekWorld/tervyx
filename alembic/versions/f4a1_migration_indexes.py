"""complete indexes declared by the alert-group, detection and history models

Revision ID: f4a1_migration_indexes
Revises: f4a_incident_enrichment
"""

from collections.abc import Sequence

from alembic import op

revision: str = "f4a1_migration_indexes"
down_revision: str | None = "f4a_incident_enrichment"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_INDEXES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "ix_alert_group_history_alert_group_id",
        "alert_group_history",
        ("alert_group_id",),
    ),
    (
        "ix_alert_group_history_organization_id",
        "alert_group_history",
        ("organization_id",),
    ),
    ("ix_alert_groups_organization_id", "alert_groups", ("organization_id",)),
    (
        "ix_detection_rule_configurations_organization_id",
        "detection_rule_configurations",
        ("organization_id",),
    ),
    (
        "ix_detection_rule_metrics_organization_id",
        "detection_rule_metrics",
        ("organization_id",),
    ),
    (
        "ix_detection_suppressions_organization_id",
        "detection_suppressions",
        ("organization_id",),
    ),
    ("ix_incident_history_incident_id", "incident_history", ("incident_id",)),
    ("ix_incident_history_organization_id", "incident_history", ("organization_id",)),
)


def upgrade() -> None:
    for name, table, columns in _INDEXES:
        op.create_index(name, table, list(columns))


def downgrade() -> None:
    for name, table, _columns in reversed(_INDEXES):
        op.drop_index(name, table_name=table)
