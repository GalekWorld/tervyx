import pytest

from tests.conftest import TEST_USER_ID


@pytest.mark.parametrize(
    ("method", "path", "payload"),
    [
        (
            "post",
            "/api/v1/auth/token",
            {
                "organization_slug": "test-org",
                "email": "admin@test.local",
                "password": "test-password",
                "organization_id": "attacker-controlled",
            },
        ),
        (
            "post",
            "/api/v1/identity-providers",
            {
                "provider_type": "entra",
                "name": "test-idp",
                "issuer": "https://issuer.example.test",
                "client_id": "client",
                "client_secret_reference": "vault://tenants/test/idp",
                "allowed_redirect_uris": ["https://soc.example.test/callback"],
                "is_active": True,
            },
        ),
        (
            "post",
            "/api/v1/integrations",
            {
                "integration_type": "wazuh",
                "name": "test-integration",
                "base_url": "https://wazuh.example.test",
                "credential_reference": "vault://tenants/test/wazuh",
                "organization_id": "attacker-controlled",
            },
        ),
        (
            "put",
            "/api/v1/detection-rules/suspicious_powershell",
            {
                "enabled": True,
                "suppression_window_seconds": 60,
                "configuration": {},
                "active": False,
            },
        ),
        (
            "put",
            f"/api/v1/users/{TEST_USER_ID}/capabilities/security.read",
            {"effect": "allow", "organization_id": "attacker-controlled"},
        ),
    ],
)
def test_sensitive_inputs_reject_internal_fields(client, method, path, payload) -> None:
    response = getattr(client, method)(path, json=payload)
    assert response.status_code == 422


@pytest.mark.parametrize(
    ("path", "payload"),
    [
        (
            "/api/v1/incidents/00000000-0000-0000-0000-000000000001/status",
            {"status": "open", "severity": 10},
        ),
        (
            "/api/v1/alert-groups/00000000-0000-0000-0000-000000000001/status",
            {"status": "open", "assigned_to": None},
        ),
        (
            "/api/v1/investigations/00000000-0000-0000-0000-000000000001/status",
            {"status": "completed", "organization_id": "attacker-controlled"},
        ),
    ],
)
def test_lifecycle_inputs_reject_internal_fields(client, path, payload) -> None:
    response = client.patch(path, json=payload)
    assert response.status_code == 422
