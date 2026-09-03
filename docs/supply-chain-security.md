# Supply chain and release security — FASE 2.9

## Reproducible inputs

`requirements.txt` and `requirements-dev.txt` are human-maintained input
constraints. `requirements.lock` and `requirements-dev.lock` are generated
with `pip-compile --generate-hashes` and are the only dependency files used by
runtime images and CI. The production image uses an immutable Python Alpine
digest and `pip --require-hashes`; therefore a changed package, hash or base
image fails the build. `apk upgrade` deliberately applies current Alpine
security fixes at build time: the resulting immutable image digest and SBOM
are the deployable release record. A mirrored Alpine snapshot for byte-for-byte
source rebuilds remains a tracked operational improvement.

Dependency updates are submitted as a dedicated pull request: update input
constraints, regenerate both locks using Python 3.11, run `pip-audit`, inspect
the SBOM diff, and obtain security review for major versions or any CVE
exception. No `--ignore-unfixed` exception is allowed for a fixed critical/high
application dependency. Base image digest updates follow the same process.

## CI gates

Every pull request must pass lock freshness, Black, Ruff, mypy, tests/RLS
integration tests, Alembic check, Bandit, Semgrep, strict `pip-audit`, Trivy,
Gitleaks, restore drill and ZAP. HIGH/CRITICAL Trivy findings, leaked secrets,
ERROR-level Semgrep findings and test failures block merging.

The CI audit uses `pip-audit --strict --progress-spinner off --timeout 30`.
Dependency collection or advisory-service timeout is therefore a failed gate,
not a warning or an implicit pass.

## Releases, SBOM and signatures

Only a protected `v*` tag can run the release workflow. It pushes the image by
tag and digest to GHCR, generates an SPDX JSON SBOM with Syft, stores it as a
release workflow artifact, creates a GitHub build-provenance attestation, and
signs the immutable image digest with Cosign keyless OIDC. Deployment admission
must verify the Cosign issuer is GitHub Actions and the identity is this
repository before pulling an image.

## Required repository settings

GitHub branch protection cannot be enforced by repository files. Protect the
default branch with: pull request required, one security-code-owner approval,
all CI checks required, no force push/deletion, signed commits where available,
and restrict tag creation matching `v*` to release maintainers. Configure a
`production` GitHub Environment with required reviewer approval before any
deployment job is added.
