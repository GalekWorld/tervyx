from datetime import UTC, datetime
from unittest.mock import Mock

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import Alert, SecurityEvent
from tests.conftest import OTHER_ORG_ID, OTHER_USER_ID, TEST_ORG_ID, TEST_USER_ID, auth_headers


def h(org=TEST_ORG_ID):
    user_id = OTHER_USER_ID if org == OTHER_ORG_ID else TEST_USER_ID
    return auth_headers(user_id, org)


def create_integration(client: TestClient):
    return client.post(
        "/api/v1/integrations",
        headers=h(),
        json={
            "integration_type": "wazuh",
            "name": "Primary Wazuh",
            "base_url": "https://wazuh.example:55000",
            "credential_reference": "WAZUH_TEST_SECRET",
        },
    )


def test_integration_crud_is_tenant_scoped_and_does_not_leak_reference(client: TestClient) -> None:
    created = create_integration(client)
    assert created.status_code == 201
    body = created.json()
    assert "credential_reference" not in body
    assert "WAZUH_TEST_SECRET" not in created.text
    entity_id = body["id"]
    assert (
        client.get(f"/api/v1/integrations/{entity_id}", headers=h(OTHER_ORG_ID)).status_code == 404
    )
    assert client.get("/api/v1/integrations", headers=h()).json()[0]["id"] == entity_id
    assert client.get(f"/api/v1/integrations/{entity_id}/status", headers=h()).status_code == 200


def test_sync_and_test_enqueue_jobs(client: TestClient, monkeypatch) -> None:
    entity_id = create_integration(client).json()["id"]
    fake = Mock(id="job-123")
    monkeypatch.setattr("app.api.router.enqueue_task", Mock(return_value=fake))
    assert client.post(f"/api/v1/integrations/{entity_id}/test", headers=h()).status_code == 202
    assert client.post(f"/api/v1/integrations/{entity_id}/sync", headers=h()).status_code == 202


def test_event_and_alert_pagination_and_filters(
    client: TestClient, session: Session, endpoint
) -> None:
    now = datetime.now(UTC)
    for i in range(5):
        session.add(
            SecurityEvent(
                organization_id=TEST_ORG_ID,
                endpoint_id=endpoint.id,
                source="wazuh" if i < 4 else "other",
                external_id=f"page-event-{i}",
                event_type="test",
                severity=i,
                occurred_at=now,
                raw_payload={},
            )
        )
    session.add(
        Alert(
            organization_id=TEST_ORG_ID,
            endpoint_id=endpoint.id,
            source="wazuh",
            external_id="filter-alert",
            title="Filtered",
            severity=9,
            status="open",
            occurred_at=now,
        )
    )
    session.commit()
    response = client.get("/api/v1/events?page=2&page_size=2&source=wazuh", headers=h())
    assert response.status_code == 200
    assert len(response.json()) == 2
    assert response.headers["X-Total-Count"] == "4"
    alerts = client.get("/api/v1/alerts?severity=9&status=open", headers=h())
    assert len(alerts.json()) == 1
