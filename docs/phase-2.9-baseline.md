# FASE 2.9 validation baseline

This baseline records the local validation performed for the Phase 2.9
hardening changes. It is intentionally a release-input record, not a claim
that a local workstation has published or signed a production artifact.

## Validation

- Dependency locks: regenerated with `pip-compile --generate-hashes` and
  installed with `pip --require-hashes --dry-run`.
- Application quality: Black, Ruff and mypy passed; all 67 collected tests
  completed as 66 passed / 1 intentionally skipped, with 81% application
  coverage. The real-Wazuh test is skipped when its optional endpoint is not
  configured. The focused offensive group completed 24 passed / 0 failed.
- Database: `alembic upgrade head` and `alembic check` passed. The Compose
  backup/restore drill completed successfully.
- Runtime hardening: API, Celery worker, Beat, migration and backup containers
  ran with non-root users, dropped Linux capabilities and read-only root filesystems
  where compatible. Gateway startup was validated after its writable temporary
  directories were moved to owned tmpfs mounts.
- Image scan: Trivy found zero HIGH and zero CRITICAL vulnerabilities in the
  final `soc-phase-2.9:latest` image.
- Source scans: Bandit, Semgrep, Gitleaks and pip-audit passed. ZAP baseline
  passed against the locally started API.
- SBOM: Syft produced and parsed an SPDX JSON SBOM for the final image (124
  package entries in this local build).

## Release verification boundary

The release workflow creates a GitHub OIDC keyless Cosign signature only when
a protected `v*` tag is pushed to GHCR. Local validation verifies the workflow
syntax, the pinned Cosign CLI and generated SBOM, but cannot mint GitHub OIDC
identity or publish a signed GHCR digest. See `supply-chain-security.md` for
the required repository controls and verification policy.
