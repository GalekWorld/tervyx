from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import Endpoint
from tests.conftest import OTHER_ORG_ID, OTHER_USER_ID, TEST_ORG_ID, auth_headers


def test_organizations_cannot_read_each_others_endpoints(
    client: TestClient, session: Session
) -> None:
    tenant_a_endpoint = Endpoint(
        organization_id=TEST_ORG_ID,
        hostname="tenant-a-host",
        agent_id="shared-agent-id",
        status="active",
    )
    tenant_b_endpoint = Endpoint(
        organization_id=OTHER_ORG_ID,
        hostname="tenant-b-host",
        agent_id="shared-agent-id",
        status="active",
    )
    session.add_all([tenant_a_endpoint, tenant_b_endpoint])
    session.commit()

    tenant_a_headers = {"X-Organization-ID": str(TEST_ORG_ID)}
    response = client.get("/api/v1/endpoints", headers=tenant_a_headers)
    assert [item["hostname"] for item in response.json()] == ["tenant-a-host"]

    forbidden_lookup = client.get(
        f"/api/v1/endpoints/{tenant_b_endpoint.id}", headers=tenant_a_headers
    )
    assert forbidden_lookup.status_code == 404


def test_ingested_external_ids_are_isolated_per_organization(
    client: TestClient, wazuh_payload: dict
) -> None:
    request = {"source": "wazuh", "payload": wazuh_payload}
    response_a = client.post(
        "/api/v1/events",
        headers={"X-Organization-ID": str(TEST_ORG_ID)},
        json=request,
    )
    response_b = client.post(
        "/api/v1/events",
        headers=auth_headers(OTHER_USER_ID, OTHER_ORG_ID),
        json=request,
    )

    assert response_a.status_code == response_b.status_code == 201
    assert response_a.json()["event"]["id"] != response_b.json()["event"]["id"]
    assert response_b.json()["duplicate"] is False
