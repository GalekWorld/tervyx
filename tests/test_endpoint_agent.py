from pathlib import Path

import pytest

from app.services.endpoint_agent import EndpointAgentError, EndpointAgentService
from tests.conftest import OTHER_ORG_ID


def test_windows_agent_release_contract_is_present():
    root = Path(__file__).parents[1]
    assert (root / "agent/windows/Installer/Product.wxs").is_file()
    assert (root / "agent/windows/apply-update.ps1").is_file()
    assert (root / ".github/workflows/windows-agent.yml").is_file()


def test_enrolment_heartbeat_and_revocation_are_single_identity_and_audited(session, endpoint):
    service = EndpointAgentService(session)
    enrolled, token = service.enroll(
        endpoint.organization_id, endpoint.id, endpoint.organization_id
    )
    assert token and enrolled.identity_key
    service.heartbeat(
        endpoint.organization_id,
        enrolled.identity_key,
        token,
        {"service": "healthy"},
        "1.0.0",
        None,
    )
    session.commit()
    assert endpoint.last_seen is not None
    service.revoke(endpoint.organization_id, endpoint.id, endpoint.organization_id, "test")
    session.commit()
    with pytest.raises(EndpointAgentError):
        service.heartbeat(endpoint.organization_id, endpoint.identity_key, token, {}, "1.0.0", None)


def test_wrong_token_and_cross_tenant_are_rejected(session, endpoint):
    service = EndpointAgentService(session)
    enrolled, token = service.enroll(
        endpoint.organization_id, endpoint.id, endpoint.organization_id
    )
    with pytest.raises(EndpointAgentError):
        service.heartbeat(endpoint.organization_id, endpoint.identity_key, "wrong", {}, None, None)
    with pytest.raises(EndpointAgentError):
        service.heartbeat(OTHER_ORG_ID, enrolled.identity_key, token, {}, None, None)
    with pytest.raises(EndpointAgentError):
        service.enroll(OTHER_ORG_ID, endpoint.id, endpoint.organization_id)


def test_agent_api_enrolment_and_heartbeat(client, endpoint):
    response = client.post("/api/v1/endpoints/enroll", json={"endpoint_id": str(endpoint.id)})
    assert response.status_code == 200
    payload = response.json()
    heartbeat = client.post(
        f"/api/v1/endpoints/agent/{payload['identity_key']}/heartbeat",
        headers={
            "X-Agent-Token": payload["enrollment_token"],
            "X-Agent-Organization-Id": payload["organization_id"],
        },
        json={"health": {"service": "healthy"}, "agent_version": "1.0"},
    )
    assert heartbeat.status_code == 200
    foreign = client.post(
        f"/api/v1/endpoints/agent/{payload['identity_key']}/heartbeat",
        headers={
            "X-Agent-Token": payload["enrollment_token"],
            "X-Agent-Organization-Id": str(OTHER_ORG_ID),
        },
        json={"health": {}},
    )
    assert foreign.status_code == 401
