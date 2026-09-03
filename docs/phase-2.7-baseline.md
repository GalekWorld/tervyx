# Phase 2.7 validation baseline

Validated: 2026-09-01 (Europe/Madrid)

## Scope delivered

- Enterprise OIDC Authorization Code + PKCE with Entra ID as the strict first provider and a
  provider-neutral model for Okta, Google, Keycloak and generic OIDC.
- Entra `tid`/`oid` binding, issuer pinning, nonce/state validation, RS256/ES256 JWKS validation
  and mandatory MFA evidence for production administrators.
- Database-backed revocable sessions, refresh-token/session binding, logout and global logout.
- Capability authorization layered over `admin`, `analyst` and `viewer`.
- Tenant-scoped secret reads and rotation for Vault KV v2, OpenBao KV v2 and AWS Secrets Manager;
  environment secrets remain development-only.
- Audited emergency tenant/user revocation command with optional OIDC provider shutdown.
- RLS migration for all new identity/session/capability tables.

## Tests and quality

- Full suite with real PostgreSQL 16, Redis 7, Vault 1.21.4, OpenBao 2.6.1 and Wazuh 4.14.7:
  **60 passed, 0 skipped, 0 failed**.
- Coverage: **83.31%** (2,193 statements, 366 missed), above the 80% CI gate.
- Black: 67 files unchanged; Ruff: 0 findings; mypy: 49 source files clean.
- Alembic upgraded to `c91f2a7d4e60`; `alembic check` found no pending operations.
- Docker build passed; image `soc-api:latest`, ID
  `sha256:e606ece8e3f020f22e5ef8a77e39a6911ccadada5c153765cbe9e8aa5572f78f`.
- PostgreSQL custom-format backup/restore drill passed against the new schema.

Adversarial coverage includes cross-tenant user/session/provider/secret access, IDOR, manipulated
tenant/session claims, missing administrator MFA, replayed OIDC state, wrong nonce/Entra tenant,
capability escalation/deny overrides, secret namespace escape and secret leakage.

## Secrets validation

- Vault KV v2 real read + versioned rotation: passed.
- OpenBao KV v2 real read + versioned rotation: passed using the official 2.6.1 container.
- AWS Secrets Manager provider contract: passed with the boto3 API, workload provider chain,
  `AWSCURRENT` rotation semantics and enforced tenant prefix. A live AWS-account smoke test is not
  run in local/CI because no cloud account or IAM role is attached; deployment must execute the
  same contract once with a least-privilege role before first AWS-backed tenant activation.
- Environment backend is rejected in production; Vault/OpenBao reject non-TLS addresses there.

## Wazuh regression E2E

The real pipeline `Wazuh -> Client -> Adapter -> Celery -> PostgreSQL -> API` passed after the
CredentialStore interface change:

- agents: fetched 1, processed 1, failed 0, 504 ms;
- alerts: fetched 187, processed 187, failed 0, 3,165 ms;
- database/API: 1 endpoint and 187 events/alerts, API total 187.

## Security gates

- Bandit high/high gate: 0 findings.
- Semgrep Python/security-audit: 65 rules, 49 Python targets, 0 findings.
- pip-audit: 0 known runtime vulnerabilities.
- Trivy fixed HIGH/CRITICAL gate: 0 findings in Debian 13.6 and Python packages.
- Gitleaks: 1.19 MB scanned, 0 leaks after replacing a laboratory token literal with a CI variable.
- OWASP ZAP: 51 URLs, 0 failures, 66 passes, one non-blocking cacheability warning on auth/error
  responses.

## Remaining production validation

- Entra end-to-end login requires a customer/laboratory Entra tenant, application registration and
  Conditional Access policy. The signed-token/JWKS/tenant/MFA contract is automated, but interactive
  federation cannot be completed without that external tenant.
- Live AWS Secrets Manager validation requires an attached least-privilege AWS IAM role. The SDK
  contract is automated and no AWS credentials are stored in this repository or CI.
