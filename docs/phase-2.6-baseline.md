# Phase 2.6 final baseline

Status: **CLOSED**
Validated: 2026-09-01 (Europe/Madrid)

## Validation environment

- Docker Desktop Engine 29.3.1, Linux containers, x86_64.
- PostgreSQL 16 Alpine, Redis 7 Alpine and Vault 1.21.4 recreated with empty project volumes.
- Wazuh manager and indexer 4.14.7 from the official single-node Docker deployment.
- Python 3.11.4 and pytest 9.1.1 on the host validation environment.

## Tests and migrations

- `pytest --cov=app --cov-report=xml --cov-fail-under=80`: 44 passed, 0 skipped,
  0 failed; coverage 83.17% (1598 statements, 269 missed).
- Real integration coverage included PostgreSQL/RLS/idempotency, Redis, Vault KV v2 and
  the Wazuh manager/indexer contract.
- Alembic upgraded an empty PostgreSQL database through all revisions to
  `b76d20e732f1`.
- `alembic check`: no new upgrade operations detected.
- Black: 61 files unchanged. Ruff: all checks passed. mypy: 44 source files clean.

## Security scans

- Bandit high-severity/high-confidence gate: 0 findings (0 medium/high; 2 low metrics).
- Semgrep: 65 Python/security rules over 44 files, 0 findings.
- pip-audit: 0 known runtime dependency vulnerabilities.
- Gitleaks: 906.62 KB scanned, 0 leaks.
- Trivy image scan with fixed vulnerabilities only and HIGH/CRITICAL gate: 0 findings
  in Debian 13.6 and Python packages.
- OWASP ZAP baseline against the deployed OpenAPI API: 37 URLs, 0 failures, 65 passes,
  2 non-blocking warnings (non-storable authentication/error responses and authentication
  request identification).

## Container image

- Clean `--no-cache` build passed.
- Image: `autonomous-soc:v0.2.6`.
- Image ID: `sha256:8dbfc04726e4559e62963912fb3402c9926fa9449ecbd2b60e9f0b571eb748e3`.
- Size: 90,539,802 bytes.
- Final Docker build context: 8.12 KB.

## Wazuh E2E

The real flow `Wazuh -> WazuhClient -> WazuhAdapter -> Celery -> PostgreSQL -> API`
passed with manager authentication, agent retrieval, indexer pagination, certificate/error
handling and API consistency checks.

- Agents fetched/processed: 1/1; failures 0; duration 1,232 ms.
- Alerts fetched/processed: 187/187; duplicates 0; failures 0; duration 4,066 ms.
- PostgreSQL totals: 1 endpoint, 187 events, 187 alerts.
- API alert total: 187.

The development override allowlists `host.docker.internal` plus its explicitly supplied
current `/32` and `/128` addresses. Production SSRF policy remains unchanged.

## Backup and restore

- Custom-format `pg_dump` created and validated with `pg_restore --list`.
- Restore into a new temporary PostgreSQL database passed with `--exit-on-error`.
- Organization data and Alembic version were queried successfully after restore.
- Temporary restore database was removed.
- Measured drill duration: 5.60 seconds.

## Productive ingestion benchmark

| Events | Persisted | Errors | Throughput | p50 | p95 | p99 | Max queue | Blocked DB locks |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10,000 | 10,000 | 0 | 248.59 events/s | 22,371.916 ms | 38,526.249 ms | 39,804.948 ms | 1,050 | 0 |
| 100,000 | 100,000 | 0 | 249.63 events/s | 189,934.674 ms | 372,873.529 ms | 392,506.397 ms | 7,724 | 0 |

The 1M run was intentionally not executed on the development host. No performance
optimization is part of this closure.
