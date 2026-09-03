"""Regression checks for duplicate foreign-key creation across revisions."""

import ast
from pathlib import Path

VERSIONS = Path(__file__).parents[1] / "alembic" / "versions"


def _created_foreign_keys(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or node.name != "upgrade":
            continue
        for call in ast.walk(node):
            if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute):
                continue
            if not isinstance(call.func.value, ast.Name) or call.func.value.id != "op":
                continue
            if call.func.attr != "create_foreign_key" or not call.args:
                continue
            name = call.args[0]
            if isinstance(name, ast.Constant) and isinstance(name.value, str):
                names.append(name.value)
    return names


def test_upgrade_chain_does_not_create_named_foreign_key_twice() -> None:
    created: dict[str, Path] = {}
    duplicates: list[str] = []
    for migration in sorted(VERSIONS.glob("*.py")):
        for name in _created_foreign_keys(migration):
            if name in created:
                duplicates.append(f"{name}: {created[name].name} and {migration.name}")
            created[name] = migration
    message = "duplicate foreign-key creation in upgrade chain: " + "; ".join(duplicates)
    assert not duplicates, message


def test_integration_rows_keep_direct_and_tenant_scoped_foreign_keys() -> None:
    tenant_migration = (VERSIONS / "m_asvs_tenant_integration_fks.py").read_text(encoding="utf-8")
    for name in (
        "fk_dlq_tenant_integration",
        "fk_checkpoints_tenant_integration",
        "dead_letter_events_organization_id_fkey",
        "integration_checkpoints_organization_id_fkey",
    ):
        assert f'"{name}"' in tenant_migration
