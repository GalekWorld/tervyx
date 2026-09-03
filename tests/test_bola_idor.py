from datetime import UTC, datetime
from uuid import UUID

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.auth import hash_password
from app.models import DeadLetterEvent, Endpoint, IntegrationAccount, User
from tests.conftest import OTHER_ORG_ID, TEST_ORG_ID, auth_headers


def _integration(org):
    return IntegrationAccount(
        organization_id=org,
        integration_type="wazuh",
        name=f"wazuh-{org}",
        base_url="https://wazuh.example.test",
        credential_reference=f"env://tenant-{org}",
    )


def test_id_endpoints_are_tenant_scoped_and_non_enumerating(
    client: TestClient, session: Session, endpoint: Endpoint
) -> None:
    foreign_endpoint = Endpoint(
        organization_id=OTHER_ORG_ID,
        hostname="foreign-host",
        operating_system="Linux",
        ip_address="10.0.0.20",
        agent_id="foreign-agent",
        status="active",
    )
    local_integration = _integration(TEST_ORG_ID)
    foreign_integration = _integration(OTHER_ORG_ID)
    session.add_all([foreign_endpoint, local_integration, foreign_integration])
    session.flush()
    now = datetime.now(UTC)
    foreign_dlq = DeadLetterEvent(
        organization_id=OTHER_ORG_ID,
        integration_account_id=foreign_integration.id,
        payload={"event": "foreign"},
        error="parse failure",
        first_failed_at=now,
        last_failed_at=now,
        status="pending",
    )
    session.add(foreign_dlq)
    session.commit()

    # Existing local resources are readable, while foreign and unknown IDs are
    # indistinguishable to the tenant and therefore cannot be enumerated.
    assert client.get(f"/api/v1/endpoints/{endpoint.id}").status_code == 200
    assert client.get(f"/api/v1/endpoints/{foreign_endpoint.id}").status_code == 404
    assert client.get("/api/v1/endpoints/00000000-0000-0000-0000-000000000099").status_code == 404
    assert client.get(f"/api/v1/integrations/{foreign_integration.id}").status_code == 404
    assert client.get(f"/api/v1/integrations/{foreign_integration.id}/status").status_code == 404
    assert client.get(f"/api/v1/dead-letters/{foreign_dlq.id}").status_code == 404
    assert client.post(f"/api/v1/dead-letters/{foreign_dlq.id}/reprocess").status_code == 404
    assert client.post(f"/api/v1/dead-letters/{foreign_dlq.id}/discard").status_code == 404


def test_id_endpoints_enforce_capabilities_before_resource_access(
    client: TestClient, session: Session
) -> None:
    analyst_id = UUID("30000000-0000-0000-0000-000000000003")
    session.add(
        User(
            id=analyst_id,
            organization_id=TEST_ORG_ID,
            email="analyst-bola@test.local",
            display_name="BOLA Analyst",
            role="analyst",
            password_hash=hash_password("test-password"),
        )
    )
    integration = _integration(TEST_ORG_ID)
    session.add(integration)
    session.commit()
    analyst_headers = auth_headers(
        user_id=analyst_id,
        organization_id=TEST_ORG_ID,
        role="analyst",
    )
    assert (
        client.post(
            f"/api/v1/integrations/{integration.id}/rotate-secret",
            headers=analyst_headers,
            json={"credentials": {"client_secret": "new"}},
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/v1/dead-letters/00000000-0000-0000-0000-000000000099/discard",
            headers=analyst_headers,
        ).status_code
        == 403
    )
