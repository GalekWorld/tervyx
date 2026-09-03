"""add indexes declared by the PAM/JIT ORM models

Revision ID: pam_jit_indexes
Revises: endpoint_agent_platform
"""

from collections.abc import Sequence

from alembic import op

revision: str = "pam_jit_indexes"
down_revision: str | None = "endpoint_agent_platform"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_INDEXES = (
    ("ix_platform_admin_eligibilities_organization_id", "platform_admin_eligibilities", ["organization_id"]),
    ("ix_platform_admin_eligibilities_user_id", "platform_admin_eligibilities", ["user_id"]),
    ("ix_privileged_access_policies_organization_id", "privileged_access_policies", ["organization_id"]),
    ("ix_privileged_access_requests_organization_id", "privileged_access_requests", ["organization_id"]),
    ("ix_privileged_access_requests_requester_id", "privileged_access_requests", ["requester_id"]),
    ("ix_privileged_access_requests_approver_id", "privileged_access_requests", ["approver_id"]),
    ("ix_privileged_sessions_organization_id", "privileged_sessions", ["organization_id"]),
    ("ix_privileged_sessions_user_id", "privileged_sessions", ["user_id"]),
    ("ix_privileged_sessions_base_session_id", "privileged_sessions", ["base_session_id"]),
)


def upgrade() -> None:
    for name, table, columns in _INDEXES:
        op.create_index(name, table, columns, unique=False)


def downgrade() -> None:
    for name, table, _columns in reversed(_INDEXES):
        op.drop_index(name, table_name=table)
