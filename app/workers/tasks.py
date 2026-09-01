import logging
import time
import uuid
from datetime import UTC, datetime

from celery import Task
from redis import Redis
from sqlalchemy import select

from app.core.auth import create_worker_token, decode_token
from app.core.credentials import get_credential_store
from app.core.database import SessionLocal, set_tenant_context
from app.core.security import safe_error, sanitize
from app.integrations.registry import AdapterRegistry
from app.integrations.wazuh import WazuhAdapter
from app.models import DeadLetterEvent, Endpoint, IntegrationAccount, Organization
from app.services.ingestion import IngestionService
from app.services.integrations import IntegrationService
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)
MAX_RETRIES = 5


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
                token = create_worker_token(organization_id, account.id)
                sync_wazuh_agents.delay(str(account.id), token)
                sync_wazuh_alerts.delay(str(account.id), token)
                dispatched += 2
            session.rollback()
    return {"status": "scheduled", "dispatched": dispatched}


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
    autoretry_for=(Exception,),
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
    autoretry_for=(Exception,),
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
            sync_wazuh_agents.delay(str(account.id), worker_token)
        return result


@celery_app.task(
    bind=True,
    autoretry_for=(Exception,),
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
        processed = duplicates = failed = 0
        for payload in page.items:
            try:
                ingest_result = IngestionService(session, AdapterRegistry([WazuhAdapter()])).ingest(
                    account.organization_id, "wazuh", payload
                )
                duplicates += int(ingest_result.duplicate)
                processed += 1
            except Exception:
                session.rollback()
                failed += 1
                process_security_event.delay(str(account.id), payload, worker_token)
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
            sync_wazuh_alerts.delay(str(account.id), worker_token)
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
