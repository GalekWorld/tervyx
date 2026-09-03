import logging
from typing import Any

import sentry_sdk
from opentelemetry import metrics, trace
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from prometheus_client import Counter, Histogram

from app.core.config import get_settings
from app.core.security import sanitize

logger = logging.getLogger(__name__)

HTTP_REQUESTS = Counter("soc_http_requests_total", "HTTP requests", ["method", "path", "status"])
HTTP_DURATION = Histogram(
    "soc_http_request_duration_seconds", "HTTP request duration", ["method", "path"]
)
TASK_EXECUTIONS = Counter("soc_task_executions_total", "Celery task executions", ["task", "status"])
HEALTH_CHECKS = Counter("soc_health_checks_total", "Health probe results", ["probe", "status"])
_SENTRY_INITIALIZED = False


def _sentry_before_send(event: Any, _hint: dict[str, Any]) -> Any:
    """Keep exception telemetry useful without shipping secrets or PII."""
    scrubbed = sanitize(event)

    def redact_pii(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                str(key): (
                    "[REDACTED]"
                    if str(key).lower() in {"email", "ip", "ip_address", "client_ip", "user_agent"}
                    else redact_pii(item)
                )
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [redact_pii(item) for item in value]
        return value

    scrubbed = redact_pii(scrubbed)
    if isinstance(scrubbed, dict):
        request = scrubbed.get("request")
        if isinstance(request, dict):
            for key in ("headers", "cookies", "data", "query_string"):
                if key in request:
                    request[key] = "[REDACTED]"
    return scrubbed


def _configure_sentry(settings) -> None:
    global _SENTRY_INITIALIZED
    if _SENTRY_INITIALIZED or not settings.sentry_dsn:
        return
    sentry_sdk.init(
        dsn=settings.sentry_dsn,
        environment=settings.sentry_environment or settings.app_env,
        release=settings.sentry_release or None,
        traces_sample_rate=settings.sentry_traces_sample_rate,
        send_default_pii=False,
        before_send=_sentry_before_send,
    )
    _SENTRY_INITIALIZED = True


def configure_telemetry(application, engine) -> None:
    settings = get_settings()
    if settings.app_env == "test":
        return
    _configure_sentry(settings)
    if settings.otel_exporter_otlp_endpoint:
        resource = Resource.create(
            {"service.name": settings.app_name, "deployment.environment": settings.app_env}
        )
        provider = TracerProvider(resource=resource)
        provider.add_span_processor(
            BatchSpanProcessor(OTLPSpanExporter(endpoint=settings.otel_exporter_otlp_endpoint))
        )
        trace.set_tracer_provider(provider)
        metrics.set_meter_provider(
            MeterProvider(
                resource=resource,
                metric_readers=[
                    PeriodicExportingMetricReader(
                        OTLPMetricExporter(endpoint=settings.otel_exporter_otlp_endpoint),
                        export_interval_millis=settings.otel_metrics_export_interval_seconds * 1000,
                    )
                ],
            )
        )
    FastAPIInstrumentor.instrument_app(
        application, excluded_urls="health/live,health/ready,metrics"
    )
    SQLAlchemyInstrumentor().instrument(engine=engine)


def instrument_celery(celery_app) -> None:
    """Attach Sentry and bounded task counters to every worker replica."""
    settings = get_settings()
    if settings.app_env != "test":
        _configure_sentry(settings)
    from celery.signals import task_failure, task_postrun, task_prerun

    @task_prerun.connect(weak=False)
    def _task_start(task_id=None, task=None, **_kwargs):
        if task:
            task.request._tervyx_started = True

    @task_postrun.connect(weak=False)
    def _task_done(task_id=None, task=None, **_kwargs):
        if task:
            TASK_EXECUTIONS.labels(task.name, "success").inc()

    @task_failure.connect(weak=False)
    def _task_failed(task_id=None, task=None, **_kwargs):
        if task:
            TASK_EXECUTIONS.labels(task.name, "failure").inc()
