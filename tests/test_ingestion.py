from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.integrations.registry import AdapterRegistry
from app.integrations.wazuh import WazuhAdapter
from app.models import Alert, AuditLog, Endpoint, SecurityEvent
from app.services.ingestion import IngestionService
from tests.conftest import TEST_ORG_ID


def test_ingestion_creates_endpoint_event_alert_and_audit(
    session: Session, wazuh_payload: dict
) -> None:
    result = IngestionService(session, AdapterRegistry([WazuhAdapter()])).ingest(
        TEST_ORG_ID, "wazuh", wazuh_payload
    )

    assert result.duplicate is False
    assert result.organization_id == TEST_ORG_ID
    assert result.alert is not None
    assert session.scalar(select(func.count()).select_from(Endpoint)) == 1
    assert session.scalar(select(func.count()).select_from(SecurityEvent)) == 1
    assert session.scalar(select(func.count()).select_from(Alert)) == 1
    assert session.scalar(select(func.count()).select_from(AuditLog)) == 1


def test_ingestion_is_idempotent(session: Session, wazuh_payload: dict) -> None:
    service = IngestionService(session, AdapterRegistry([WazuhAdapter()]))
    first = service.ingest(TEST_ORG_ID, "wazuh", wazuh_payload)
    second = service.ingest(TEST_ORG_ID, "wazuh", wazuh_payload)

    assert first.event.id == second.event.id
    assert second.duplicate is True
    assert session.scalar(select(func.count()).select_from(SecurityEvent)) == 1


def test_batch_ingestion_is_atomic_and_deduplicates_within_a_page(
    session: Session, wazuh_payload: dict
) -> None:
    second = {**wazuh_payload, "id": "wazuh-1700000000.124"}
    result = IngestionService(session, AdapterRegistry([WazuhAdapter()])).ingest_batch(
        TEST_ORG_ID, "wazuh", [wazuh_payload, wazuh_payload, second]
    )

    assert result.processed_count == 2
    assert result.duplicate_count == 1
    assert result.failed_count == 0
    assert session.scalar(select(func.count()).select_from(SecurityEvent)) == 2
