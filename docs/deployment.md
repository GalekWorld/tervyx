# Deployment

## Variables obligatorias

- `JWT_PRIVATE_KEY_PATH`, `JWT_PUBLIC_KEY_PATH` y `JWT_ACTIVE_KID`; RSA de 3072 bits recomendado.
- `JWT_VERIFICATION_KEYS_JSON`: claves públicas anteriores durante rotación sin downtime.
- `POSTGRES_OWNER_PASSWORD`: solo migraciones.
- `POSTGRES_APP_PASSWORD`: API, worker y beat.
- `DATABASE_URL`, Redis broker/backend y `ALLOWED_HOSTS`.
- `CORS_ORIGINS`: lista explícita; vacío si no hay cliente web.
- `OTEL_EXPORTER_OTLP_ENDPOINT`: collector OTLP/HTTP, si existe.
- `CREDENTIAL_STORE_BACKEND`: `environment`, `vault` o `aws_secrets_manager`.

## Despliegue seguro

1. Provisionar PostgreSQL/Redis privados, TLS, backups y cifrado en reposo.
2. Crear un rol propietario para Alembic y otro runtime sin `BYPASSRLS`.
3. Ejecutar `alembic upgrade head` como job único antes del rollout.
4. Desplegar API, workers y un único Beat; el lock Redis protege solapamientos accidentales.
5. Configurar probes en `/health/live` y `/health/ready`; no usar `/health` como readiness.
6. Restringir `/metrics` a la red de observabilidad y enviar OTLP al collector.
7. Ejecutar el contenedor como usuario no root y limitar egress a Wazuh y servicios necesarios.

Docker Compose es un entorno de desarrollo serio, no alta disponibilidad. Redis usa AOF, pero
producción requiere Sentinel/cluster o servicio gestionado. Beat y workers deben tener una cola
durable y políticas de shutdown para respetar `acks_late`.

## Backup y recuperación

Compose genera cada 24 h un `pg_dump` custom, valida su catálogo y conserva siete días. Los
scripts `scripts/backup_restore_drill.ps1` y `.sh` crean una base temporal, restauran con
`--exit-on-error`, verifican datos y versión Alembic y la eliminan. Restore local medido: 6,26 s.
RPO inicial: 24 h; RTO objetivo: 2 h. Para reducir RPO, `docker/postgres/pitr.conf.example`
documenta WAL archiving/base backup, pero PITR no se declara activo hasta disponer de un almacén
WAL externo, cifrado, versionado y probado.

## TLS y secretos

TLS termina en el ingress/gateway gestionado en producción; PostgreSQL, Redis, Vault y Wazuh
deben usar TLS/mTLS según soporte. `docker-compose.vault.yml` es exclusivamente un contract test
HTTP local. La rotación JWT consiste en publicar primero la nueva pública, cambiar `kid` y clave
privada del firmante, esperar la expiración máxima y retirar la pública antigua.

## Verificación previa al rollout

```bash
black --check app tests scripts
ruff check app tests scripts
mypy app
alembic upgrade head
alembic check
pytest --cov=app --cov-fail-under=80
pip-audit -r requirements.txt
docker build -t autonomous-soc:candidate .
```

El E2E con Wazuh necesita un entorno autorizado de laboratorio. Si no se proporcionan sus
variables, pytest lo marca como omitido y ejecuta los contract tests del cliente/adapter.
