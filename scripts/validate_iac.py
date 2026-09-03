"""Dependency-free guardrails for the provider-neutral OpenTofu contract."""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IAC = ROOT / "infra" / "tofu"
REQUIRED = {
    "versions.tf",
    "variables.tf",
    "main.tf",
    "backend.hcl.example",
    "environments/staging.tfvars.example",
    "environments/production.tfvars.example",
}
# References (for example `secret_reference_prefix`) are allowed; literal
# credentials are not.
FORBIDDEN_SECRET = re.compile(
    r"(?i)(password|token|private_key|client_secret)\s*=\s*[\"'][^\"']+\""
)


def main() -> int:
    missing = [path for path in REQUIRED if not (IAC / path).is_file()]
    if missing:
        print(f"Missing IaC contract files: {', '.join(missing)}")
        return 1
    invalid = [
        path
        for path in IAC.rglob("*.tf*")
        if not path.name.endswith(".example") and path.suffix in {".tfvars", ".hcl"}
    ]
    if invalid:
        print(
            "Real IaC variables/backend config must not be committed: "
            + ", ".join(map(str, invalid))
        )
        return 1
    for path in IAC.rglob("*"):
        if path.is_file() and path.suffix in {".tf", ".tfvars", ".hcl"}:
            if FORBIDDEN_SECRET.search(path.read_text(encoding="utf-8")):
                print(f"Potential inline secret in IaC: {path}")
                return 1
    main_tf = (IAC / "main.tf").read_text(encoding="utf-8")
    required_controls = ("private_endpoint", "tls_verify_full", "pitr_enabled", "external_backend")
    if any(control not in main_tf for control in required_controls):
        print("IaC security preconditions are incomplete")
        return 1
    print("IaC static contract validation passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
