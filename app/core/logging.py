import logging
import sys

from pythonjsonlogger.json import JsonFormatter

from app.core.security import sanitize


class SanitizingJsonFormatter(JsonFormatter):
    """Redact structured Celery and application log fields before emission."""

    def add_fields(self, log_record, record, message_dict) -> None:  # type: ignore[no-untyped-def]
        super().add_fields(log_record, record, message_dict)
        log_record.update(sanitize(log_record))


def configure_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(SanitizingJsonFormatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.INFO)
