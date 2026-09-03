import json
from unittest.mock import Mock

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.auth import create_worker_token
from app.integrations.wazuh.client import WazuhPage
from app.models import DeadLetterEvent, IntegrationAccount, IntegrationCheckpoint
from app.workers.tasks import process_security_event, sync_wazuh_alerts
from tests.conftest import TEST_ORG_ID


def account(session: Session) -> IntegrationAccount:
    item = IntegrationAccount(
        organization_id=TEST_ORG_ID,
        integration_type="wazuh",
        name="Worker Wazuh",
        base_url="https://wazuh.example:55000",
        credential_reference="WORKER_WAZUH_CREDS",
        enabled=True,
        status="configured",
    )
    session.add(item)
    session.commit()
    return item


def test_checkpoint_recovery_and_duplicate_processing(
    session: Session, wazuh_payload: dict, monkeypatch
) -> None:
    item = account(session)
    worker_token = create_worker_token(item.organization_id, item.id)
    checkpoint = IntegrationCheckpoint(
        organization_id=TEST_ORG_ID,
        integration_account_id=item.id,
        stream="alerts",
        last_position="0",
        cursor={"search_after": ["old", "cursor"]},
    )
    session.add(checkpoint)
    session.commit()
    fake_client = Mock()
    fake_client.fetch_alerts.return_value = WazuhPage(
        [wazuh_payload, wazuh_payload], ["new", "cursor"]
    )
    monkeypatch.setenv("WORKER_WAZUH_CREDS", json.dumps({"username": "u", "password": "p"}))
    monkeypatch.setattr("app.workers.tasks.SessionLocal", lambda: session)
    monkeypatch.setattr(
        "app.services.integrations.IntegrationService.client", lambda self, acc: fake_client
    )
    result = sync_wazuh_alerts.run(str(item.id), worker_token)
    assert result["processed_count"] == 2
    assert result["duplicate_count"] == 1
    assert fake_client.fetch_alerts.call_args.kwargs["cursor"] == ["old", "cursor"]
    recovered = session.scalar(
        select(IntegrationCheckpoint).where(IntegrationCheckpoint.id == checkpoint.id)
    )
    assert recovered.cursor == {"search_after": ["new", "cursor"]}


def test_malformed_event_is_dead_lettered(session: Session, monkeypatch) -> None:
    item = account(session)
    worker_token = create_worker_token(item.organization_id, item.id)
    fake_client = Mock()
    fake_client.fetch_alerts.return_value = WazuhPage([{"password": "must-not-leak"}], None)
    monkeypatch.setenv("WORKER_WAZUH_CREDS", json.dumps({"username": "u", "password": "p"}))
    monkeypatch.setattr("app.workers.tasks.SessionLocal", lambda: session)
    monkeypatch.setattr(
        "app.services.integrations.IntegrationService.client", lambda self, acc: fake_client
    )
    queued = Mock()
    monkeypatch.setattr("app.workers.tasks.enqueue_task", queued)
    result = sync_wazuh_alerts.run(str(item.id), worker_token)
    assert result["failed_count"] == 1
    queued.assert_called_once_with(
        process_security_event, str(item.id), {"password": "must-not-leak"}, worker_token
    )


def test_event_is_dead_lettered_only_after_retry_exhaustion(session: Session, monkeypatch) -> None:
    item = account(session)
    worker_token = create_worker_token(item.organization_id, item.id)
    monkeypatch.setattr("app.workers.tasks.SessionLocal", lambda: session)
    process_security_event.push_request(retries=5)
    try:
        result = process_security_event.run(
            str(item.id), {"password": "must-not-leak"}, worker_token
        )
    finally:
        process_security_event.pop_request()
    dead = session.scalar(select(DeadLetterEvent))
    assert result == {"status": "dead_lettered"}
    assert dead.payload["password"] == "[REDACTED]"
    assert dead.attempts == 6


def test_process_worker_schedules_exponential_retry(session: Session, monkeypatch) -> None:
    item = account(session)
    worker_token = create_worker_token(item.organization_id, item.id)
    monkeypatch.setattr("app.workers.tasks.SessionLocal", lambda: session)
    retry = Mock(side_effect=RuntimeError("retry scheduled"))
    monkeypatch.setattr(process_security_event, "retry", retry)
    try:
        process_security_event.run(str(item.id), {"malformed": True}, worker_token)
    except RuntimeError as exc:
        assert str(exc) == "retry scheduled"
    retry.assert_called_once()
    assert retry.call_args.kwargs["countdown"] == 1
