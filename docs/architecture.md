# Arquitectura de Fase 2.6

El dominio no importa módulos Wazuh. `WazuhClient` solo realiza HTTP, `WazuhAdapter` convierte
payloads al contrato `NormalizedSecurityRecord` y `IngestionService` persiste objetos internos.
El registro de adapters conserva el punto de extensión sin añadir proveedores en esta fase.

## Flujo de ingestión

1. Celery Beat obtiene cuentas habilitadas y publica jobs firmados con tenant e integración.
2. El worker valida el token interno y vuelve a cargar la cuenta bajo RLS.
3. `WazuhClient` autentica y obtiene agentes/alertas con timeout y backoff.
4. `WazuhAdapter` normaliza; Pydantic/contratos validan el límite del dominio.
5. `IngestionService` restaura el contexto RLS, busca el identificador externo y persiste.
6. Las restricciones únicas `(organization_id, source, external_id)` resuelven carreras.
7. Se actualiza el checkpoint solo después del procesamiento y se registra el resumen del job.
8. Tras agotar reintentos, el payload sanitizado entra en DLQ para operación manual.

Los checkpoints conservan posición, timestamp, cursor y última ejecución correcta. La
sincronización de alertas puede continuar por `search_after`; la de agentes por offset.

## Procesos y disponibilidad

- `/health/live` prueba únicamente que el proceso responde.
- `/health/ready` requiere PostgreSQL y Redis.
- `/metrics` expone contadores y latencias HTTP Prometheus, incluyendo probes de
  salud y ejecuciones Celery.
- OpenTelemetry instrumenta FastAPI y SQLAlchemy y exporta traces/metrics por
  OTLP/HTTP; Sentry captura excepciones, releases y fallos de workers cuando se
  configura su DSN.
- Los logs JSON llevan campos del job (`integration_id`, `organization_id`, `job_id`, conteos y
  duración) y los errores se sanitizan.

La API no realiza HTTP a Wazuh. Los workers usan límites de tiempo Celery y los clientes aplican
la política común de timeout, reintentos con backoff exponencial/jitter, circuit breaker,
bulkhead y tratamiento explícito de errores retryable/no-retryable (401/403, 429 y 5xx).
Los detalles y límites operativos están en `docs/connector-resilience.md`.

## Segmentación

PostgreSQL y Redis viven únicamente en `backend` (red interna). La API tampoco tiene egress y
solo se publica mediante el gateway Nginx. Únicamente los workers unen `backend` con
`integration_egress`. El allowlist de hostname y CIDR se vuelve a resolver inmediatamente antes
de cada cliente para reducir SSRF y DNS rebinding. Los metadata endpoints, loopback, link-local,
multicast y rangos privados no autorizados quedan bloqueados.
