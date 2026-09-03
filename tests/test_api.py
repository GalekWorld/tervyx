from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import Alert, Incident, Investigation
from tests.conftest import TEST_ORG_ID


def headers(org_id=TEST_ORG_ID) -> dict[str, str]:
    return {"X-Organization-ID": str(org_id)}


def test_health_does_not_require_tenant(client: TestClient) -> None:
    assert client.get("/health").json() == {"status": "ok"}


def test_endpoint_routes(client: TestClient, endpoint) -> None:
    response = client.get("/api/v1/endpoints", headers=headers())
    assert response.status_code == 200
    assert len(response.json()) == 1

    response = client.get(f"/api/v1/endpoints/{endpoint.id}", headers=headers())
    assert response.status_code == 200
    assert response.json()["hostname"] == "host-01"


def test_alert_incident_and_investigation_routes(
    client: TestClient, session: Session, endpoint
) -> None:
    alert = Alert(
        organization_id=TEST_ORG_ID,
        endpoint_id=endpoint.id,
        source="test",
        external_id="api-alert",
        title="API alert",
        severity=8,
        status="open",
        occurred_at=datetime.now(UTC),
    )
    incident = Incident(
        organization_id=TEST_ORG_ID,
        title="API incident",
        severity=8,
        status="open",
        occurred_at=datetime.now(UTC),
        alerts=[alert],
    )
    session.add_all([alert, incident])
    session.flush()
    investigation = Investigation(
        organization_id=TEST_ORG_ID,
        alert_id=alert.id,
        risk_score=85,
        classification="malicious",
        confidence=0.9,
        evidence=[{"type": "event"}],
        explanation="Test explanation",
        recommended_actions=[{"action": "review", "requires_approval": True}],
        status="completed",
    )
    session.add(investigation)
    session.commit()

    assert len(client.get("/api/v1/alerts", headers=headers()).json()) == 1
    assert client.get(f"/api/v1/alerts/{alert.id}", headers=headers()).status_code == 200
    incident_response = client.get(f"/api/v1/incidents/{incident.id}", headers=headers())
    assert incident_response.status_code == 200
    assert incident_response.json()["alert_ids"] == [str(alert.id)]
    assert client.get("/api/v1/incidents", headers=headers()).status_code == 200
    assert (
        client.get(f"/api/v1/investigations/{investigation.id}", headers=headers()).status_code
        == 200
    )
    created = client.post(f"/api/v1/incidents/{incident.id}/investigation", headers=headers())
    assert created.status_code == 201
    generated_id = created.json()["id"]
    assert created.json()["incident_id"] == str(incident.id)
    assert (
        client.patch(
            f"/api/v1/investigations/{generated_id}/status",
            headers=headers(),
            json={"status": "closed"},
        ).status_code
        == 200
    )


def test_post_events(client: TestClient, wazuh_payload: dict) -> None:
    response = client.post(
        "/api/v1/events",
        headers=headers(),
        json={"source": "wazuh", "payload": wazuh_payload},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["duplicate"] is False
    assert body["event"]["source"] == "wazuh"
    assert body["alert"]["severity"] == 8


def test_tenant_header_is_required(client: TestClient) -> None:
    authorization = client.headers.pop("Authorization")
    try:
        response = client.get("/api/v1/endpoints")
    finally:
        client.headers["Authorization"] = authorization
    assert response.status_code == 401
