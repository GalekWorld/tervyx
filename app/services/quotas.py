import json
import uuid
from datetime import UTC, datetime
from typing import Any, cast

from redis import Redis
from redis.exceptions import RedisError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import TenantQuota, TenantUsageLedger


class TenantQuotaExceeded(RuntimeError):
    pass


class TenantQuotaUnavailable(RuntimeError):
    pass


def utc_day_start(value: datetime | None = None) -> datetime:
    now = value or datetime.now(UTC)
    return now.astimezone(UTC).replace(hour=0, minute=0, second=0, microsecond=0)


class QuotaService:
    """Durable tenant limits, reserved atomically at batch boundaries."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def quota(self, organization_id: uuid.UUID, *, lock: bool = False) -> TenantQuota:
        statement = select(TenantQuota).where(TenantQuota.organization_id == organization_id)
        if lock:
            statement = statement.with_for_update()
        quota = self.session.scalar(statement)
        if quota is not None:
            return quota
        settings = get_settings()
        quota = TenantQuota(
            organization_id=organization_id,
            max_events_per_day=settings.tenant_default_max_events_per_day,
            max_jobs_per_minute=settings.tenant_default_max_jobs_per_minute,
            max_api_requests_per_minute=settings.tenant_default_max_api_requests_per_minute,
            max_storage_bytes=settings.tenant_default_max_storage_bytes,
            max_queue_depth=settings.tenant_default_max_queue_depth,
        )
        self.session.add(quota)
        self.session.flush()
        return quota

    def reserve_ingestion(
        self, organization_id: uuid.UUID, *, events: int, byte_count: int
    ) -> None:
        if events < 0 or byte_count < 0:
            raise ValueError("Quota reservations cannot be negative")
        quota = self.quota(organization_id, lock=True)
        if not quota.enabled:
            raise TenantQuotaExceeded("Tenant ingestion is disabled")
        period_start = utc_day_start()
        usage = self.session.scalar(
            select(TenantUsageLedger)
            .where(
                TenantUsageLedger.organization_id == organization_id,
                TenantUsageLedger.period_start == period_start,
            )
            .with_for_update()
        )
        if usage is None:
            usage = TenantUsageLedger(organization_id=organization_id, period_start=period_start)
            self.session.add(usage)
            self.session.flush()
        usage.events_ingested = int(usage.events_ingested or 0)
        usage.hot_storage_bytes = int(usage.hot_storage_bytes or 0)
        usage.archived_storage_bytes = int(usage.archived_storage_bytes or 0)
        usage.jobs_dispatched = int(usage.jobs_dispatched or 0)
        if usage.events_ingested + events > quota.max_events_per_day:
            raise TenantQuotaExceeded("Daily event quota exceeded")
        storage_used = int(
            self.session.scalar(
                select(
                    func.coalesce(
                        func.sum(
                            TenantUsageLedger.hot_storage_bytes
                            + TenantUsageLedger.archived_storage_bytes
                        ),
                        0,
                    )
                ).where(TenantUsageLedger.organization_id == organization_id)
            )
            or 0
        )
        if storage_used + byte_count > quota.max_storage_bytes:
            raise TenantQuotaExceeded("Tenant storage quota exceeded")
        usage.events_ingested += events
        usage.hot_storage_bytes += byte_count

    def record_archive(
        self, organization_id: uuid.UUID, *, hot_bytes: int, archive_bytes: int
    ) -> None:
        usage = self._usage(organization_id)
        usage.hot_storage_bytes = max(0, usage.hot_storage_bytes - hot_bytes)
        usage.archived_storage_bytes += archive_bytes

    def release_hot_storage(self, organization_id: uuid.UUID, byte_count: int) -> None:
        usage = self._usage(organization_id)
        usage.hot_storage_bytes = max(0, usage.hot_storage_bytes - byte_count)

    def allow_job(self, redis: Redis, organization_id: uuid.UUID) -> bool:
        quota = self.quota(organization_id)
        if not quota.enabled:
            return False
        now = datetime.now(UTC)
        key = f"quota:jobs:{organization_id}:{now.strftime('%Y%m%d%H%M')}"
        try:
            count = int(cast(Any, redis.incr(key)))
            if count == 1:
                redis.expire(key, 120)
        except RedisError as exc:
            raise TenantQuotaUnavailable("Tenant job quota service is unavailable") from exc
        if count > quota.max_jobs_per_minute:
            return False
        usage = self._usage(organization_id)
        usage.jobs_dispatched = int(usage.jobs_dispatched or 0) + 1
        return True

    def queue_limit(self, organization_id: uuid.UUID) -> int:
        return self.quota(organization_id).max_queue_depth

    def allow_api(self, redis: Redis, organization_id: uuid.UUID) -> bool:
        """A fail-closed per-tenant API quota; intentionally not a DB transaction."""
        quota = self.quota(organization_id)
        key = f"quota:api:{organization_id}:{datetime.now(UTC).strftime('%Y%m%d%H%M')}"
        try:
            count = int(cast(Any, redis.incr(key)))
            if count == 1:
                redis.expire(key, 120)
        except RedisError as exc:
            raise TenantQuotaUnavailable("Tenant API quota service is unavailable") from exc
        return quota.enabled and count <= quota.max_api_requests_per_minute

    def _usage(self, organization_id: uuid.UUID) -> TenantUsageLedger:
        period_start = utc_day_start()
        usage = self.session.scalar(
            select(TenantUsageLedger).where(
                TenantUsageLedger.organization_id == organization_id,
                TenantUsageLedger.period_start == period_start,
            )
        )
        if usage is None:
            usage = TenantUsageLedger(organization_id=organization_id, period_start=period_start)
            self.session.add(usage)
        return usage


def payload_byte_count(payload: dict) -> int:
    return len(json.dumps(payload, separators=(",", ":"), default=str).encode("utf-8"))
