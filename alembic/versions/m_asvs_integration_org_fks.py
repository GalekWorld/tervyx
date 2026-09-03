"""Compatibility revision for integration foreign-key hardening.

``m_asvs_tenant_integration_fks`` already creates both the composite,
tenant-scoped foreign keys and the direct ``organization_id`` foreign keys
for these tables.  This revision is retained in the chain for databases that
already recorded it, but intentionally performs no DDL.

Revision ID: m_asvs_integration_org_fks
Revises: m_asvs_tenant_integration_fks
"""
from collections.abc import Sequence

revision: str = "m_asvs_integration_org_fks"
down_revision: str | None = "m_asvs_tenant_integration_fks"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # The preceding revision owns these constraints.  Do not recreate them.
    pass


def downgrade() -> None:
    # Compatibility revision: no DDL was applied by upgrade().
    pass
