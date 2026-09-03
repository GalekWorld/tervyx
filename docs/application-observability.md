# Application Observability

La observabilidad es una capa operativa y no reemplaza `AuditLog`,
`SecuritySignal` ni el audit ledger.

- **Sentry:** `SENTRY_DSN`, `SENTRY_ENVIRONMENT`, `SENTRY_RELEASE` y
  `SENTRY_TRACES_SAMPLE_RATE` se inyectan desde el gestor de secretos. FastAPI,
  excepciones no controladas y workers se asocian al release y entorno. En
  producción el arranque falla si el DSN HTTPS no está configurado.
- **OpenTelemetry:** `OTEL_EXPORTER_OTLP_ENDPOINT` exporta traces FastAPI,
  SQLAlchemy y métricas OTLP con `service.name` y entorno. Prometheus conserva
  `/metrics` para scraping local/operativo.
- **Workers/jobs:** contadores por tarea y estado (`success`/`failure`), límites
  Celery ya existentes y Sentry por proceso permiten alertar sobre errores,
  retries y colas degradadas en cada réplica.
- **Correlación:** `X-Request-ID` se conserva en respuestas, logs, errores y
  eventos `security.http_denied`; el tenant y actor se propagan desde el JWT y
  el span. Los IDs se limitan a 128 caracteres.
- **403/404:** las respuestas autenticadas relevantes generan un `AuditLog`
  `security.http_denied`, que self-monitoring puede agrupar como enumeración.
  Las rutas no autenticadas no inventan un tenant y sólo generan log seguro.
- **Redacción:** Sentry no envía PII por defecto; request headers, cookies,
  query/body y campos sensibles se redactan antes de emitir. El formatter JSON
  aplica `sanitize` y no se registran credenciales.
- **Health/degradation:** `/health/live` sólo prueba proceso; `/health/ready`
  valida PostgreSQL y Redis, incrementa métricas y devuelve 503 sin detalles
  internos cuando hay degradación.

## Multi-réplica y alertas

Cada API/worker replica exporta con el mismo nombre lógico de servicio y un
resource detector del entorno; el collector agrega por `instance`/pod. Alertas
recomendadas: tasa de excepciones Sentry, p95/p99 HTTP, ratio 5xx, readiness
degradada, fallos de tareas, backlog/retries, ausencia de heartbeat y pérdida
de export OTLP. La deduplicación y routing de estas alertas se configura en
Sentry/collector/Prometheus externo.
