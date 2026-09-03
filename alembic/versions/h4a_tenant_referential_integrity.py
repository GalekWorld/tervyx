"""hardening A tenant-scoped referential integrity

Revision ID: h4a_tenant_referential_integrity
Revises: f4b_investigation_engine
"""

from collections.abc import Sequence

from alembic import op

revision: str = "h4a_tenant_referential_integrity"
down_revision: str | None = "f4b_investigation_engine"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_PARENT_KEYS: tuple[tuple[str, str], ...] = (
    ("uq_users_organization_id", "users"),
    ("uq_endpoints_organization_id", "endpoints"),
    ("uq_alerts_organization_id", "alerts"),
    ("uq_alert_groups_organization_id", "alert_groups"),
    ("uq_incidents_organization_id", "incidents"),
)

_TENANT_FOREIGN_KEYS: tuple[tuple[str, str, tuple[str, ...], str, tuple[str, ...]], ...] = (
    (
        "fk_events_tenant_endpoint",
        "security_events",
        ("organization_id", "endpoint_id"),
        "endpoints",
        ("organization_id", "id"),
    ),
    (
        "fk_alerts_tenant_endpoint",
        "alerts",
        ("organization_id", "endpoint_id"),
        "endpoints",
        ("organization_id", "id"),
    ),
    (
        "fk_alert_groups_tenant_assignee",
        "alert_groups",
        ("organization_id", "assigned_to"),
        "users",
        ("organization_id", "id"),
    ),
    (
        "fk_alert_group_history_tenant_group",
        "alert_group_history",
        ("organization_id", "alert_group_id"),
        "alert_groups",
        ("organization_id", "id"),
    ),
    (
        "fk_alert_group_history_tenant_actor",
        "alert_group_history",
        ("organization_id", "actor_id"),
        "users",
        ("organization_id", "id"),
    ),
    (
        "fk_incidents_tenant_assignee",
        "incidents",
        ("organization_id", "assigned_to"),
        "users",
        ("organization_id", "id"),
    ),
    (
        "fk_incident_history_tenant_incident",
        "incident_history",
        ("organization_id", "incident_id"),
        "incidents",
        ("organization_id", "id"),
    ),
    (
        "fk_incident_history_tenant_actor",
        "incident_history",
        ("organization_id", "actor_id"),
        "users",
        ("organization_id", "id"),
    ),
    (
        "fk_incident_enrichments_tenant_incident",
        "incident_enrichments",
        ("organization_id", "incident_id"),
        "incidents",
        ("organization_id", "id"),
    ),
    (
        "fk_investigations_tenant_alert",
        "investigations",
        ("organization_id", "alert_id"),
        "alerts",
        ("organization_id", "id"),
    ),
    (
        "fk_investigations_tenant_incident",
        "investigations",
        ("organization_id", "incident_id"),
        "incidents",
        ("organization_id", "id"),
    ),
)


def upgrade() -> None:
    for name, table in _PARENT_KEYS:
        op.create_unique_constraint(name, table, ["organization_id", "id"])
    for name, table, columns, referenced_table, referenced_columns in _TENANT_FOREIGN_KEYS:
        op.create_foreign_key(
            name, table, referenced_table, list(columns), list(referenced_columns)
        )


def downgrade() -> None:
    for name, table, _columns, _referenced_table, _referenced_columns in reversed(
        _TENANT_FOREIGN_KEYS
    ):
        op.drop_constraint(name, table, type_="foreignkey")
    for name, table in reversed(_PARENT_KEYS):
        op.drop_constraint(name, table, type_="unique")
