from celery import Celery

from app.core.config import get_settings
from app.core.logging import configure_logging
from app.core.observability import instrument_celery

settings = get_settings()
configure_logging()
celery_app = Celery(
    "autonomous_soc",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["app.workers.tasks"],
)
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    task_track_started=True,
    task_time_limit=300,
    task_soft_time_limit=270,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    worker_hijack_root_logger=False,
    beat_schedule={
        "periodic-wazuh-sync": {
            "task": "schedule_wazuh_syncs",
            "schedule": settings.sync_interval_seconds,
        },
        "periodic-retention-archive": {
            "task": "archive_retention_data",
            "schedule": 3600,
        },
        "periodic-self-monitoring": {
            "task": "evaluate_self_monitoring",
            "schedule": 60,
        },
    },
)
instrument_celery(celery_app)
