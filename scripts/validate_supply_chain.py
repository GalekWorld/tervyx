"""Static, dependency-free supply-chain gate for repository controls."""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    windows_workflow = (ROOT / ".github/workflows/windows-agent.yml").read_text(encoding="utf-8")
    owners = (ROOT / ".github/CODEOWNERS").read_text(encoding="utf-8")
    admission = ROOT / "infra/policies/tervyx-admission.yaml"
    required_release = (
        "id-token: write",
        "attestations: write",
        "packages: write",
        "provenance: true",
        "sbom: true",
        "cosign sign",
        "steps.build.outputs.digest",
    )
    if any(value not in release for value in required_release):
        print("Release workflow is missing a signing/SBOM/provenance control")
        return 1
    required_ci = (
        "alembic upgrade head",
        "alembic check",
        "pytest --cov=app",
        "semgrep scan",
        "aquasec/trivy@",
        "gitleaks@",
        "zaproxy@",
        "restore-drill.log",
    )
    if any(value not in ci for value in required_ci):
        print("CI workflow is missing a required PRE-AI gate")
        return 1
    if "dotnet publish" not in windows_workflow or "wix build" not in windows_workflow:
        print("Windows agent workflow must publish .NET and build WiX MSI")
        return 1
    if "/qn" not in windows_workflow or "/norestart" not in windows_workflow:
        print("Windows agent workflow must include silent MSI install validation")
        return 1
    workflow_dir = ROOT / ".github/workflows"
    for workflow in workflow_dir.glob("*.yml"):
        actions = re.findall(r"uses:\s+([^\s]+)@([^\s#]+)", workflow.read_text(encoding="utf-8"))
        if any(not re.fullmatch(r"[0-9a-f]{40}", ref) for _action, ref in actions):
            print(f"Every workflow action must use an immutable SHA: {workflow}")
            return 1
    if "/infra/" not in owners or "/.github/workflows/" not in owners:
        print("Infrastructure and workflow CODEOWNERS are required")
        return 1
    if not admission.is_file() or "REPLACE_WITH" not in admission.read_text(encoding="utf-8"):
        print("Admission policy must remain an explicit provider placeholder until configured")
        return 1
    print("Supply-chain repository controls validation passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
