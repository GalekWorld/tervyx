# FASE 2.8 baseline

Fecha: 2026-09-01. Entorno: PostgreSQL 16, Redis 7, Celery con dos workers,
20 tenants y batches de 500 eventos. Beat se detuvo durante las cargas para
eliminar tráfico periódico de la medición.

| Carga | Persistidos | Errores | events/s | p50 | p95 | p99 | Cola máx. | Locks bloqueados |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10.000 | 10.000 | 0 | 817,83 | 8,84 s | 11,61 s | 11,87 s | 2 | 0 |
| 100.000 | 100.000 | 0 | 657,03 | 81,72 s | 145,92 s | 150,55 s | 176 | 3 transitorios |
| 500.000 | 500.000 | 0 | ~860 | 294,38 s | 540,95 s | 566,22 s | 826 observada | 0 en muestreos |

El percentil 500k usa 485.580 muestras de telemetría Redis: la escritura de
telemetría es best-effort y perdió muestras bajo presión, mientras que el conteo
durable PostgreSQL confirmó 500.000 persistidos. El harness ahora finaliza por
conteo durable, que es la fuente autoritativa.

Picos muestreados: PostgreSQL 1,34 GiB, Redis 315 MiB y cada worker 1,01 GiB;
la base alcanzó 1,19 GiB durante 500k. El host local tiene 7,64 GiB y la
proyección del millón es de aproximadamente 20 minutos de carga sostenida:
1M no se ejecutó por no ser seguro/reproducible en este host. Debe ejecutarse
en staging.

Se añadió un índice inverso de `alert_security_events.security_event_id` para
que la purga por cascada de cargas grandes no degrade cuadráticamente.

Validaciones de aislamiento: la suite cubre RLS PostgreSQL, idempotencia
concurrente, cuotas por tenant, fair queue, backpressure y archivo write-then-
delete. No se observó pérdida silenciosa ni duplicados durante las cargas.

La imagen de aplicación se redujo a una base fijada `python:3.11-alpine3.21`
y se actualiza con `apk upgrade`. Trivy 0.69.3 contra la imagen final informó
0 hallazgos HIGH/CRITICAL. El workflow CI mantiene fallo por ese umbral.

Vault y OpenBao se restauraron y sus contract tests locales volvieron a pasar.
La línea base final incluye `64 passed, 1 skipped` (el único skip es Wazuh E2E
cuando no se inyectan sus credenciales locales), formato, lint, tipos,
migraciones, cobertura total del 80 % y la prueba de restauración PostgreSQL.

Bandit no encontró hallazgos high-confidence/high-severity; `pip-audit`,
Semgrep y Gitleaks terminaron correctamente (sin dependencias vulnerables,
findings ERROR o secretos). ZAP baseline contra la API desplegada terminó
correctamente. Tras una recreación de API se detectó una IP de upstream Nginx
obsoleta; se cambió a resolución DNS dinámica de Compose y se validó la
recuperación de `/health/ready`.
