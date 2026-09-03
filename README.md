# Autonomous SOC — Fase 2.9

Baseline de validación: [docs/phase-2.7-baseline.md](docs/phase-2.7-baseline.md).

Backend multi-tenant endurecido para ingestión Wazuh: FastAPI, PostgreSQL con RLS, Redis,
Celery y Alembic. Esta fase no incluye IA/LLM, frontend ni respuesta automática.

## Inicio rápido

```bash
cp .env.example .env
# Define POSTGRES_OWNER_PASSWORD, POSTGRES_APP_PASSWORD y DEMO_ADMIN_PASSWORD.
# Compose genera una clave RSA de desarrollo en un volumen; producción debe aportar la suya.
docker compose up --build -d
docker compose exec api python -m app.scripts.seed_demo
```

El contenedor `migrate` aplica Alembic con el rol propietario. API, worker y beat usan
`soc_app`, un rol sin privilegios para el que PostgreSQL fuerza RLS. No uses el propietario
ni un superusuario como identidad de runtime.

Obtén un JWT:

```bash
curl -X POST http://localhost:8000/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"organization_slug":"acme-demo","email":"analyst@acme.demo","password":"..."}'
```

Envía después `Authorization: Bearer <token>`. El tenant se obtiene exclusivamente del claim
firmado `org`; `X-Organization-ID` ya no concede contexto ni acceso.

## Componentes

```text
Wazuh -> WazuhClient -> WazuhAdapter -> IngestionService -> PostgreSQL/RLS
              |                              ^                 |
Celery Beat -> Redis -> Celery workers ------+                 +-> AuditLog/DLQ
API -> JWT/session/OIDC -> capabilities -> tenant context --------^
              +-> Prometheus metrics / OpenTelemetry / JSON logs
```

- API: consultas tenant-aware, administración de integraciones y DLQ.
- Worker: fetch, normalización, validación, deduplicación y persistencia fuera del proceso API.
- Beat: sincronización periódica protegida por lock distribuido Redis.
- PostgreSQL: unicidad por tenant y RLS como segunda frontera de aislamiento.
- Identity: OIDC/PKCE para Entra y proveedores estándar, sesiones revocables y MFA de admins.
- Secret stores: entorno local, Vault, OpenBao y AWS Secrets Manager mediante un contrato común.

Consulta [identidad y secretos](docs/identity-secrets-access.md),
[arquitectura](docs/architecture.md), [modelo de seguridad](docs/security.md),
[threat model](docs/threat-model.md), [supply chain](docs/supply-chain-security.md) y
[deployment](docs/deployment.md) para el detalle operativo.

## API y capabilities

| Método | Ruta | Capability |
|---|---|---|
| `POST` | `/api/v1/auth/token` | público, limitado por tasa |
| `POST` | `/api/v1/auth/oidc/authorize`, `/callback` | público, limitado por tasa |
| `POST` | `/api/v1/auth/logout`, `/logout-all` | sesión autenticada |
| `POST` | `/api/v1/events` | `events.ingest` |
| `GET` | `/api/v1/events`, `/endpoints`, `/alerts`, `/incidents` | `security.read` |
| `POST` | `/api/v1/integrations` | `integrations.manage` |
| `GET` | `/api/v1/integrations`, `/{id}`, `/{id}/status` | `integrations.read` |
| `POST` | `/api/v1/integrations/{id}/test`, `/{id}/sync` | `integrations.execute` |
| `POST` | `/api/v1/integrations/{id}/rotate-secret` | `secrets.rotate` |
| `POST/GET` | `/api/v1/identity-providers` | `identity.manage` |
| `GET/PUT` | `/api/v1/users/{id}/capabilities...` | `identity.manage` |
| `POST` | `/api/v1/users/{id}/sessions/revoke` | `sessions.revoke` |
| `GET` | `/health`, `/health/live`, `/health/ready`, `/metrics` | sistema |

Eventos, alertas, endpoints y DLQ aceptan paginación; `page_size` está limitado a 200.
Eventos/alertas admiten filtros de severidad, estado cuando aplica, fuente, endpoint y fechas.
El cuerpo máximo por defecto es 1 MiB y es configurable a la baja.

## Wazuh real y contract test

La referencia guardada en `IntegrationAccount` nunca contiene la credencial. Para desarrollo:

```env
CREDENTIAL_STORE_BACKEND=environment
WAZUH_ACME_CREDENTIALS={"username":"reader","password":"...","verify_ssl":true,"indexer_url":"https://indexer:9200","indexer_username":"reader","indexer_password":"..."}
```

La cuenta usa `credential_reference=env://WAZUH_ACME_CREDENTIALS`. Las URLs deben ser HTTPS,
sin credenciales embebidas y resolver solo a direcciones globales. Para una red privada de
laboratorio puede habilitarse explícitamente `ALLOW_PRIVATE_INTEGRATION_URLS=true`; nunca debe
activarse en un deployment expuesto.

El E2E real se ejecuta si existen `WAZUH_E2E_BASE_URL` y `WAZUH_E2E_CREDENTIALS` (JSON).
`docker-compose.wazuh-e2e.yml` limita la excepción SSRF del laboratorio a
`host.docker.internal` y a los `/32` o `/128` actuales indicados mediante
`WAZUH_E2E_ALLOWED_PRIVATE_CIDRS`. `python -m app.scripts.wazuh_e2e_flow` valida el
flujo manager/indexer real → cliente → adapter → Celery → PostgreSQL → API. Sin esas variables
pytest lo omite y mantiene los contract tests de auth, paginación, TLS, errores y reintentos.

## Calidad

```powershell
.\.venv\Scripts\black.exe --check app tests scripts
.\.venv\Scripts\ruff.exe check app tests scripts
.\.venv\Scripts\mypy.exe app
.\.venv\Scripts\pytest.exe --cov=app
.\.venv\Scripts\pip-audit.exe -r requirements.txt
.\.venv\Scripts\alembic.exe check
.\.venv\Scripts\python.exe -m scripts.benchmark_ingestion
```

GitHub Actions instala los locks con hashes, verifica su frescura, repite lint, formato, typing,
migración, integración con PostgreSQL/Redis/Vault, cobertura mínima del 80 %, restore y build.
Semgrep, Bandit, pip-audit, Trivy, Gitleaks y ZAP fallan el pipeline ante hallazgos relevantes
HIGH/CRITICAL. Los tags protegidos `v*` publican una imagen firmada keyless y un SBOM SPDX.
