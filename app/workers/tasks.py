import logging
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from celery import Task
from redis import Redis
from sqlalchemy import select

from app.core.auth import create_worker_token, decode_token
from app.core.credentials import get_credential_store
from app.core.database import SessionLocal, set_tenant_context
from app.core.security import safe_error, sanitize
from app.integrations.registry import AdapterRegistry
from app.integrations.wazuh import WazuhAdapter, WazuhTransientError
from app.models import DeadLetterEvent, Endpoint, IntegrationAccount, Organization
from app.services import audit_ledger  # noqa: F401 - registers the sealing listener
from app.services.archive import RetentionService
from app.services.fair_queue import BackpressureError, TenantFairQueue
from app.services.ingestion import IngestionService
from app.services.integrations import IntegrationService
from app.services.quotas import QuotaService, TenantQuotaUnavailable
from app.services.self_monitoring import SelfMonitoringService
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)
MAX_RETRIES = 5


def enqueue_task(task: Any, *args: Any):
    """Publish without exposing signed worker tokens or payloads in Celery logs."""
    return task.apply_async(args=args, argsrepr="[REDACTED]")


@celery_app.task(name="evaluate_self_monitoring")
def evaluate_self_monitoring() -> dict[str, int]:
    with SessionLocal() as session:
        organizations = list(session.scalars(select(Organization.id)))
        signal_count = 0
        for organization_id in organizations:
            signal_count += len(SelfMonitoringService(session, organization_id).evaluate())
        session.commit()
        return {"organizations": len(organizations), "signals": signal_count}


@celery_app.task(name="schedule_wazuh_syncs")
def schedule_wazuh_syncs() -> dict:
    from app.core.config import get_settings

    settings = get_settings()
    redis = Redis.from_url(settings.celery_broker_url)
    interval = max(settings.sync_interval_seconds, 30)
    lock_key = f"lock:beat:wazuh-sync:{int(time.time() // interval)}"
    if not redis.set(lock_key, str(uuid.uuid4()), nx=True, ex=interval):
        return {"status": "locked"}
    dispatched = 0
    with SessionLocal() as session:
        organization_ids = list(session.scalars(select(Organization.id)))
        for organization_id in organization_ids:
            set_tenant_context(session, organization_id)
            accounts = list(
                session.scalars(
                    select(IntegrationAccount).where(
                        IntegrationAccount.organization_id == organization_id,
                        IntegrationAccount.enabled.is_(True),
                    )
                )
            )
            for account in accounts:
                try:
                    if not QuotaService(session).allow_job(redis, organization_id):
                        logger.warning(
                            "tenant_job_quota_exceeded",
                            extra={
                                "organization_id": str(organization_id),
                                "integration_id": str(account.id),
                            },
                        )
                        continue
                except TenantQuotaUnavailable:
                    # Do not create an unbounded backlog while Redis is unhealthy.
                    logger.exception(
                        "tenant_job_quota_unavailable",
                        extra={"organization_id": str(organization_id)},
                    )
                    continue
                token = create_worker_token(organization_id, account.id)
                queue = TenantFairQueue(redis)
                limit = QuotaService(session).queue_limit(organization_id)
                try:
                    queue.enqueue(
                        organization_id,
                        {"task": "agents", "integration_id": str(account.id), "token": token},
                        max_depth=limit,
                    )
                    queue.enqueue(
                        organization_id,
                        {"task": "alerts", "integration_id": str(account.id), "token": token},
                        max_depth=limit,
                    )
                    dispatched += 2
                except BackpressureError:
                    logger.warning(
                        "tenant_sync_backpressured", extra={"organization_id": str(organization_id)}
                    )
            session.rollback()
    if dispatched:
        enqueue_task(dispatch_tenant_work)
    return {"status": "scheduled", "dispatched": dispatched}


@celery_app.task(name="dispatch_tenant_work")
def dispatch_tenant_work() -> dict:
    """Round-robin dispatch prevents one tenant monopolising the worker queue."""
    from app.core.config import get_settings

    queue = TenantFairQueue(Redis.from_url(get_settings().celery_broker_url))
    dispatched = 0
    for item in queue.dequeue_fair(get_settings().tenant_fair_dispatch_batch_size):
        if item.body.get("task") == "agents":
            enqueue_task(sync_wazuh_agents, item.body["integration_id"], item.body["token"])
        elif item.body.get("task") == "alerts":
            enqueue_task(sync_wazuh_alerts, item.body["integration_id"], item.body["token"])
        else:
            logger.error(
                "invalid_tenant_work_item", extra={"organization_id": str(item.organization_id)}
            )
            continue
        dispatched += 1
    return {"dispatched": dispatched}


@celery_app.task(name="archive_retention_data")
def archive_retention_data() -> dict:
    """Archive tenant data under the same distributed Beat lock discipline."""
    from app.core.config import get_settings

    redis = Redis.from_url(get_settings().celery_broker_url)
    lock_key = f"lock:beat:retention:{int(time.time() // 3600)}"
    if not redis.set(lock_key, str(uuid.uuid4()), nx=True, ex=3600):
        return {"status": "locked"}
    archived = purged = 0
    with SessionLocal() as session:
        for organization_id in list(session.scalars(select(Organization.id))):
            set_tenant_context(session, organization_id)
            service = RetentionService(session)
            archived += service.archive_due(organization_id).archived_events
            purged += service.purge_expired_archives(organization_id).purged_archives
            session.rollback()
    logger.info(
        "retention_archive_completed",
        extra={"archived_events": archived, "purged_archives": purged},
    )
    return {"status": "completed", "archived_events": archived, "purged_archives": purged}


def _account(session, account_id: str, worker_token: str) -> IntegrationAccount:
    payload = decode_token(worker_token, audience="autonomous-soc-worker")
    if payload.get("type") != "worker" or payload.get("integration") != account_id:
        raise ValueError("Invalid worker tenant context")
    organization_id = uuid.UUID(payload["org"])
    set_tenant_context(session, organization_id)
    account = session.scalar(
        select(IntegrationAccount).where(IntegrationAccount.id == uuid.UUID(account_id))
    )
    if account is None or account.organization_id != organization_id or not account.enabled:
        raise ValueError("Enabled integration account not found")
    return account


@celery_app.task(
    bind=True,
    autoretry_for=(WazuhTransientError,),
    retry_backoff=True,
    max_retries=3,
    name="test_wazuh_connection",
)
def test_wazuh_connection(self: Task, integration_account_id: str, worker_token: str) -> dict:
    with SessionLocal() as session:
        account = _account(session, integration_account_id, worker_token)
        service = IntegrationService(session, get_credential_store())
        try:
            health = service.client(account).test_connection()
            service.success(account)
            return {"ok": True, "integration_id": str(account.id), "health": sanitize(health)}
        except Exception as exc:
            service.failure(account, exc)
            raise


@celery_app.task(
    bind=True,
    autoretry_for=(WazuhTransientError,),
    retry_backoff=True,
    retry_backoff_max=60,
    retry_jitter=True,
    max_retries=MAX_RETRIES,
    name="sync_wazuh_agents",
)
def sync_wazuh_agents(self: Task, integration_account_id: str, worker_token: str) -> dict:
    started = time.monotonic()
    with SessionLocal() as session:
        account = _account(session, integration_account_id, worker_token)
        service = IntegrationService(session, get_credential_store())
        checkpoint = service.checkpoint(account, "agents")
        offset = int(checkpoint.last_position or 0)
        try:
            agents = service.client(account).fetch_agents(offset=offset)
        except Exception as exc:
            service.failure(account, exc)
            raise
        for raw in agents:
            agent_id = str(raw["id"])
            endpoint = session.scalar(
                select(Endpoint).where(
                    Endpoint.organization_id == account.organization_id,
                    Endpoint.agent_id == agent_id,
                )
            )
            os_data = raw.get("os") or {}
            if endpoint is None:
                endpoint = Endpoint(
                    organization_id=account.organization_id,
                    agent_id=agent_id,
                    hostname=str(raw.get("name") or agent_id),
                    status=str(raw.get("status") or "unknown"),
                )
                session.add(endpoint)
            endpoint.ip_address = raw.get("ip")
            endpoint.operating_system = os_data.get("name") if isinstance(os_data, dict) else None
            endpoint.last_seen = datetime.now(UTC)
        checkpoint.last_position = str(offset + len(agents))
        checkpoint.last_success_at = datetime.now(UTC)
        service.success(account)
        result = {
            "integration_id": str(account.id),
            "organization_id": str(account.organization_id),
            "job_id": self.request.id,
            "fetched_count": len(agents),
            "processed_count": len(agents),
            "duplicate_count": 0,
            "failed_count": 0,
            "duration_ms": round((time.monotonic() - started) * 1000),
        }
        logger.info("wazuh_agents_sync_completed", extra=result)
        if len(agents) == 500:
            enqueue_task(sync_wazuh_agents, str(account.id), worker_token)
        return result


@celery_app.task(
    bind=True,
    autoretry_for=(WazuhTransientError,),
    retry_backoff=True,
    retry_backoff_max=60,
    retry_jitter=True,
    max_retries=MAX_RETRIES,
    name="sync_wazuh_alerts",
)
def sync_wazuh_alerts(self: Task, integration_account_id: str, worker_token: str) -> dict:
    started = time.monotonic()
    with SessionLocal() as session:
        account = _account(session, integration_account_id, worker_token)
        integration_service = IntegrationService(session, get_credential_store())
        checkpoint = integration_service.checkpoint(account, "alerts")
        try:
            page = integration_service.client(account).fetch_alerts(
                since=checkpoint.last_timestamp,
                cursor=(checkpoint.cursor or {}).get("search_after"),
            )
        except Exception as exc:
            integration_service.failure(account, exc)
            raise
        batch = IngestionService(session, AdapterRegistry([WazuhAdapter()])).ingest_batch(
            account.organization_id, "wazuh", page.items
        )
        # processed_count is the number successfully handled, including safe duplicates.
        processed = batch.processed_count + batch.duplicate_count
        duplicates = batch.duplicate_count
        failed = batch.failed_count
        for payload, _error_name in batch.failures:
            enqueue_task(process_security_event, str(account.id), payload, worker_token)
        set_tenant_context(session, account.organization_id)
        checkpoint = integration_service.checkpoint(account, "alerts")
        checkpoint.cursor = {"search_after": page.cursor} if page.cursor else checkpoint.cursor
        timestamps = [str(item["timestamp"]) for item in page.items if item.get("timestamp")]
        if timestamps:
            checkpoint.last_timestamp = datetime.fromisoformat(
                max(timestamps).replace("Z", "+00:00")
            )
        checkpoint.last_success_at = datetime.now(UTC)
        integration_service.success(account)
        summary = {
            "integration_id": str(account.id),
            "organization_id": str(account.organization_id),
            "job_id": self.request.id,
            "fetched_count": len(page.items),
            "processed_count": processed,
            "duplicate_count": duplicates,
            "failed_count": failed,
            "duration_ms": round((time.monotonic() - started) * 1000),
        }
        logger.info("wazuh_alerts_sync_completed", extra=summary)
        if len(page.items) == 500 and page.cursor:
            enqueue_task(sync_wazuh_alerts, str(account.id), worker_token)
        return summary


@celery_app.task(bind=True, max_retries=MAX_RETRIES, name="process_security_event")
def process_security_event(
    self: Task, integration_account_id: str, payload: dict, worker_token: str
) -> dict:
    with SessionLocal() as session:
        account = _account(session, integration_account_id, worker_token)
        organization_id = account.organization_id
        try:
            result = IngestionService(session, AdapterRegistry([WazuhAdapter()])).ingest(
                organization_id, "wazuh", payload
            )
            _record_benchmark(payload, "ok")
            return {"event_id": str(result.event.id), "duplicate": result.duplicate}
        except Exception as exc:
            session.rollback()
            if self.request.retries >= MAX_RETRIES:
                set_tenant_context(session, organization_id)
                _dead_letter(
                    session,
                    organization_id,
                    uuid.UUID(integration_account_id),
                    payload,
                    exc,
                    self.request.retries + 1,
                )
                _record_benchmark(payload, "failed")
                return {"status": "dead_lettered"}
            raise self.retry(exc=exc, countdown=min(2**self.request.retries, 60)) from exc


@celery_app.task(bind=True, max_retries=MAX_RETRIES, name="process_security_batch")
def process_security_batch(
    self: Task, integration_account_id: str, payloads: list[dict], worker_token: str
) -> dict:
    """Celery batch task used by high-volume producers and reproducible load tests."""
    with SessionLocal() as session:
        account = _account(session, integration_account_id, worker_token)
        try:
            result = IngestionService(session, AdapterRegistry([WazuhAdapter()])).ingest_batch(
                account.organization_id, "wazuh", payloads
            )
            for payload, _error in result.failures:
                enqueue_task(process_security_event, integration_account_id, payload, worker_token)
            failed_payload_ids = {id(payload) for payload, _error in result.failures}
            for payload in payloads:
                _record_benchmark(payload, "failed" if id(payload) in failed_payload_ids else "ok")
            return {
                "processed": result.processed_count,
                "duplicates": result.duplicate_count,
                "failed": result.failed_count,
            }
        except Exception as exc:
            session.rollback()
            if self.request.retries >= MAX_RETRIES:
                for payload in payloads:
                    _dead_letter(
                        session,
                        account.organization_id,
                        uuid.UUID(integration_account_id),
                        payload,
                        exc,
                        self.request.retries + 1,
                    )
                    _record_benchmark(payload, "failed")
                return {"status": "dead_lettered", "count": len(payloads)}
            raise self.retry(exc=exc, countdown=min(2**self.request.retries, 60)) from exc


def _record_benchmark(payload: dict, status: str) -> None:
    """Emit opt-in benchmark telemetry without affecting event processing."""
    run_id = payload.get("_benchmark_run_id")
    enqueued_at = payload.get("_benchmark_enqueued_at")
    if not isinstance(run_id, str) or not isinstance(enqueued_at, (int, float)):
        return
    from app.core.config import get_settings

    try:
        redis = Redis.from_url(get_settings().celery_broker_url)
        key = f"benchmark:{run_id}:{status}"
        redis.rpush(key, f"{(time.time() - enqueued_at) * 1000:.3f}")
        redis.expire(key, 86400)
    except Exception:
        logger.warning("benchmark_telemetry_failed", extra={"benchmark_run_id": run_id})


@celery_app.task(bind=True, max_retries=MAX_RETRIES, name="reprocess_dead_letter")
def reprocess_dead_letter(self: Task, dead_letter_id: str, worker_token: str) -> dict:
    with SessionLocal() as session:
        payload = decode_token(worker_token, audience="autonomous-soc-worker")
        set_tenant_context(session, uuid.UUID(payload["org"]))
        dead = session.scalar(
            select(DeadLetterEvent).where(
                DeadLetterEvent.id == uuid.UUID(dead_letter_id), DeadLetterEvent.status == "pending"
            )
        )
        if dead is None:
            raise ValueError("Pending dead letter not found")
        account = _account(session, str(dead.integration_account_id), worker_token)
        organization_id = account.organization_id
        try:
            result = IngestionService(session, AdapterRegistry([WazuhAdapter()])).ingest(
                organization_id, "wazuh", dead.payload
            )
            set_tenant_context(session, organization_id)
            dead = session.get(DeadLetterEvent, dead.id)
            assert dead is not None
            dead.status = "reprocessed"
            session.commit()
            return {"event_id": str(result.event.id), "duplicate": result.duplicate}
        except Exception as exc:
            session.rollback()
            set_tenant_context(session, organization_id)
            dead = session.get(DeadLetterEvent, uuid.UUID(dead_letter_id))
            assert dead is not None
            dead.attempts += 1
            dead.last_failed_at = datetime.now(UTC)
            dead.error = safe_error(exc)
            session.commit()
            raise self.retry(exc=exc, countdown=min(2**self.request.retries, 60)) from exc


def _dead_letter(
    session,
    organization_id: uuid.UUID,
    integration_account_id: uuid.UUID,
    payload: dict,
    exc: Exception,
    attempts: int,
) -> None:
    now = datetime.now(UTC)
    session.add(
        DeadLetterEvent(
            organization_id=organization_id,
            integration_account_id=integration_account_id,
            payload=sanitize(payload),
            error=safe_error(exc),
            attempts=attempts,
            first_failed_at=now,
            last_failed_at=now,
            status="pending",
        )
    )
    session.commit()
