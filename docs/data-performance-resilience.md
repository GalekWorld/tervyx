# FASE 2.8 — Data, Performance & Resilience

## Ingestión y aislamiento de capacidad

Cada página Wazuh se normaliza y se persiste en una única transacción. Antes del
`flush`, se consulta la clave idempotente `(organization_id, source, external_id)`;
la restricción única de PostgreSQL sigue siendo la protección definitiva contra
carreras entre workers. Las filas repetidas de la misma página no consumen cuota.

`tenant_quotas` y `tenant_usage_ledgers` dan límites por tenant de eventos/día,
jobs/minuto, API/minuto, bytes totales y cola. La reserva de eventos y storage se
realiza con bloqueo de fila en la misma transacción que el insert. Si Redis no está
disponible, la programación de jobs y la cuota API fallan cerradas (503); no se
acepta una cola no acotada.

Celery Beat usa un lock Redis distribuido. Su planificador coloca trabajo por tenant
en una cola round-robin: en una pasada se entrega como máximo un item por tenant.
La API de sincronización manual conserva la compatibilidad de Fase 2.7, mientras que
la programación periódica recibe el reparto justo y backpressure.

## Retención y archivo

El job `archive_retention_data` archiva cada hora. Para cada tenant:

1. serializa como NDJSON comprimido los eventos de la ventana caliente;
2. escribe el objeto y calcula SHA-256;
3. crea el manifiesto `security_event_archives`, actualiza el ledger y audit log;
4. solo entonces borra los eventos calientes en el mismo commit de PostgreSQL.

Una caída antes del commit deja un objeto huérfano pero nunca pierde el evento. Una
caída de object storage detiene el job antes de tocar PostgreSQL. `filesystem` solo
es válido para desarrollo; producción exige `OBJECT_STORAGE_BACKEND=s3` y cifrado
SSE en el proveedor. La política por tenant define `archive_after_days` y
`retention_days`; los manifiestos expiran después de la retención con audit log.

Los índices de cobertura `organization_id, endpoint_id, occurred_at DESC` aceleran
consultas de endpoint por periodo. El particionado nativo no se activa sobre una
tabla existente con FKs: se requiere una migración online por table-swap, doble
escritura y validación de conteos/checksums. Es deliberadamente una operación de
infraestructura separada, no una conversión destructiva durante una migración normal.

## Backups y PITR

Las copias lógicas siguen el contenedor `backup`; para producción se exportan a un
bucket S3 independiente con Object Lock/versionado y KMS, desde una identidad que
solo puede escribir en el prefijo de backup. PITR necesita `wal_level=replica`,
`archive_mode=on`, `archive_command` hacia almacenamiento durable, base backups
periódicos y un usuario de replicación dedicado. La plantilla está en
`docker/postgres/pitr.conf.example`; el runbook exige restaurar un clon aislado,
definir `recovery_target_time`, verificar `alembic_version` y conteos, y no apuntar
nunca el restore al clúster activo.

Objetivo inicial: RPO <= 5 minutos con WAL archive y RTO <= 60 minutos para un
restore de 100 GB. Estos objetivos deben ser revalidados en el proveedor real.

## Ensayos y benchmark

`scripts/backup_restore_drill.ps1` valida restore lógico reproducible.
`scripts/run_productive_benchmark.ps1 -Count 10000|100000|500000|1000000 -Workers 2
-BatchSize 500` ejecuta PostgreSQL, Redis, Celery y batches reales. El informe JSON
incluye throughput, p50/p95/p99, profundidad máxima y locks; Docker stats del runner
expone CPU/RAM y el tamaño de volumen debe recogerse por el pipeline de staging.
El millón se ejecuta únicamente en staging dimensionado; el runner tiene timeout
explícito y reporta si el entorno no lo termina.
