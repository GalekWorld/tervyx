import json
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from jwt.algorithms import RSAAlgorithm
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.auth import create_access_token, hash_password
from app.core.config import get_settings
from app.integrations.oidc.client import OIDCClient, OIDCError, OIDCIdentity
from app.models import (
    AuditLog,
    AuthSession,
    IdentityProvider,
    IntegrationAccount,
    User,
)
from app.scripts.emergency_revoke_access import revoke_access
from tests.conftest import (
    OTHER_ORG_ID,
    OTHER_USER_ID,
    TEST_ORG_ID,
    TEST_USER_ID,
    auth_headers,
)


class FakeCredentialStore:
    def __init__(self) -> None:
        self.rotations: list[tuple[uuid.UUID, str, dict]] = []

    def get(self, organization_id: uuid.UUID, reference: str) -> dict:
        assert str(organization_id) in reference or reference.startswith("env://")
        return {"client_secret": "oidc-client-secret"}

    def rotate(self, organization_id: uuid.UUID, reference: str, value: dict) -> str:
        if str(organization_id) not in reference:
            raise AssertionError("cross-tenant secret reference")
        self.rotations.append((organization_id, reference, value))
        return "version-2"


def _login(client: TestClient, email: str = "admin@test.local") -> dict:
    response = client.post(
        "/api/v1/auth/token",
        json={
            "organization_slug": "test-org",
            "email": email,
            "password": "test-password",
        },
    )
    assert response.status_code == 200
    return response.json()


def test_session_logout_revokes_access_and_refresh(client: TestClient) -> None:
    tokens = _login(client)
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    assert client.get("/api/v1/endpoints", headers=headers).status_code == 200
    assert client.post("/api/v1/auth/logout", headers=headers).status_code == 204
    assert client.get("/api/v1/endpoints", headers=headers).status_code == 401
    assert (
        client.post(
            "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
        ).status_code
        == 401
    )


def test_global_logout_revokes_all_user_sessions(client: TestClient) -> None:
    first = _login(client)
    second = _login(client)
    first_headers = {"Authorization": f"Bearer {first['access_token']}"}
    second_headers = {"Authorization": f"Bearer {second['access_token']}"}
    assert client.post("/api/v1/auth/logout-all", headers=first_headers).status_code == 204
    assert client.get("/api/v1/endpoints", headers=first_headers).status_code == 401
    assert client.get("/api/v1/endpoints", headers=second_headers).status_code == 401


def test_capabilities_override_roles_and_enforce_idor(
    client: TestClient, session: Session, wazuh_payload: dict
) -> None:
    analyst_id = uuid.uuid4()
    viewer_id = uuid.uuid4()
    session.add_all(
        [
            User(
                id=analyst_id,
                organization_id=TEST_ORG_ID,
                email="analyst@test.local",
                display_name="Analyst",
                role="analyst",
                password_hash=hash_password("test-password"),
            ),
            User(
                id=viewer_id,
                organization_id=TEST_ORG_ID,
                email="viewer@test.local",
                display_name="Viewer",
                role="viewer",
                password_hash=hash_password("test-password"),
            ),
        ]
    )
    session.commit()

    analyst_headers = auth_headers(analyst_id, TEST_ORG_ID, "analyst")
    viewer_headers = auth_headers(viewer_id, TEST_ORG_ID, "viewer")
    assert client.post("/api/v1/integrations", headers=analyst_headers, json={}).status_code == 403
    assert client.get("/api/v1/endpoints", headers=viewer_headers).status_code == 200
    assert (
        client.put(
            f"/api/v1/users/{viewer_id}/capabilities/events.ingest",
            headers=viewer_headers,
            json={"effect": "allow"},
        ).status_code
        == 403
    )

    grant = client.put(
        f"/api/v1/users/{viewer_id}/capabilities/events.ingest",
        json={"effect": "allow"},
    )
    assert grant.status_code == 200
    assert (
        client.post(
            "/api/v1/events",
            headers=viewer_headers,
            json={"source": "wazuh", "payload": wazuh_payload},
        ).status_code
        == 201
    )
    deny = client.put(
        f"/api/v1/users/{analyst_id}/capabilities/events.ingest",
        json={"effect": "deny"},
    )
    assert deny.status_code == 200
    assert (
        client.post(
            "/api/v1/events",
            headers=analyst_headers,
            json={"source": "wazuh", "payload": wazuh_payload},
        ).status_code
        == 403
    )
    assert (
        client.put(
            f"/api/v1/users/{OTHER_USER_ID}/capabilities/security.read",
            json={"effect": "deny"},
        ).status_code
        == 404
    )
    assert client.post(f"/api/v1/users/{OTHER_USER_ID}/sessions/revoke").status_code == 404


def test_manipulated_tenant_or_session_claim_is_rejected(
    client: TestClient, session: Session
) -> None:
    assert (
        client.get(
            "/api/v1/endpoints", headers=auth_headers(TEST_USER_ID, OTHER_ORG_ID)
        ).status_code
        == 401
    )
    foreign_session = AuthSession(
        organization_id=OTHER_ORG_ID,
        user_id=OTHER_USER_ID,
        auth_method="oidc:entra",
        mfa_verified=True,
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        last_seen_at=datetime.now(UTC),
    )
    session.add(foreign_session)
    session.commit()
    token = create_access_token(
        TEST_USER_ID, TEST_ORG_ID, "admin", session_id=foreign_session.id, mfa_verified=True
    )
    assert (
        client.get("/api/v1/endpoints", headers={"Authorization": f"Bearer {token}"}).status_code
        == 401
    )


def test_production_admin_password_login_requires_sso_mfa(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(get_settings(), "app_env", "production")
    response = client.post(
        "/api/v1/auth/token",
        json={
            "organization_slug": "test-org",
            "email": "admin@test.local",
            "password": "test-password",
        },
    )
    assert response.status_code == 403


def _oidc_provider() -> IdentityProvider:
    return IdentityProvider(
        organization_id=TEST_ORG_ID,
        provider_type="entra",
        name="entra",
        issuer="https://login.microsoftonline.com/tenant-123/v2.0",
        client_id="client-123",
        client_secret_reference=f"vault://tenants/{TEST_ORG_ID}/oidc/entra",
        scopes=["openid", "profile", "email"],
        allowed_redirect_uris=["https://soc.example.test/callback"],
        enabled=True,
        enforce_mfa=True,
        provider_tenant_id="tenant-123",
    )


def test_oidc_client_validates_entra_signature_tenant_nonce_and_mfa() -> None:
    provider = _oidc_provider()
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = json.loads(RSAAlgorithm.to_jwk(private_key.public_key()))
    public_jwk.update({"kid": "entra-key-1", "alg": "RS256", "use": "sig"})
    now = datetime.now(UTC)
    claims = {
        "iss": provider.issuer,
        "aud": provider.client_id,
        "sub": "provider-subject",
        "oid": "object-123",
        "tid": "tenant-123",
        "preferred_username": "ADMIN@Test.Local",
        "name": "Admin",
        "amr": ["pwd", "mfa"],
        "nonce": "expected-nonce",
        "iat": now,
        "exp": now + timedelta(minutes=5),
    }
    token = jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": "entra-key-1"})

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "issuer": provider.issuer,
                    "authorization_endpoint": f"{provider.issuer}/authorize",
                    "token_endpoint": f"{provider.issuer}/token",
                    "jwks_uri": f"{provider.issuer}/keys",
                },
            )
        if request.url.path.endswith("/keys"):
            return httpx.Response(200, json={"keys": [public_jwk]})
        raise AssertionError(f"unexpected request: {request.url}")

    oidc = OIDCClient(
        provider,
        "never-logged",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    identity = oidc.validate_id_token(token, nonce="expected-nonce")
    assert identity.subject == "tenant-123:object-123"
    assert identity.email == "admin@test.local"
    assert identity.mfa_verified is True
    with pytest.raises(OIDCError, match="nonce"):
        oidc.validate_id_token(token, nonce="attacker-nonce")
    provider.provider_tenant_id = "attacker-tenant"
    with pytest.raises(OIDCError, match="tenant"):
        oidc.validate_id_token(token, nonce="expected-nonce")


def test_oidc_flow_enforces_admin_mfa_and_state_is_single_use(
    client: TestClient, session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    provider = _oidc_provider()
    session.add(provider)
    session.commit()

    class FakeOIDCClient:
        mfa = False

        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def authorization_url(self, **kwargs) -> str:
            return f"https://login.example.test/authorize?state={kwargs['state']}"

        def exchange_code(self, **_kwargs) -> OIDCIdentity:
            return OIDCIdentity(
                subject="tenant-123:object-123",
                email="admin@test.local",
                display_name="Admin",
                provider_tenant_id="tenant-123",
                mfa_verified=self.mfa,
                claims={},
            )

    monkeypatch.setattr("app.services.identity.OIDCClient", FakeOIDCClient)
    monkeypatch.setattr("app.api.router.get_credential_store", lambda: FakeCredentialStore())
    started = client.post(
        "/api/v1/auth/oidc/authorize",
        json={
            "organization_slug": "test-org",
            "provider_name": "entra",
            "redirect_uri": "https://soc.example.test/callback",
        },
    )
    assert started.status_code == 200
    state = started.json()["authorization_url"].split("state=", 1)[1]
    callback = {
        "state": state,
        "code": "authorization-code",
        "redirect_uri": "https://soc.example.test/callback",
    }
    assert client.post("/api/v1/auth/oidc/callback", json=callback).status_code == 401
    assert client.post("/api/v1/auth/oidc/callback", json=callback).status_code == 401

    FakeOIDCClient.mfa = True
    second = client.post(
        "/api/v1/auth/oidc/authorize",
        json={
            "organization_slug": "test-org",
            "provider_name": "entra",
            "redirect_uri": "https://soc.example.test/callback",
        },
    )
    state = second.json()["authorization_url"].split("state=", 1)[1]
    callback["state"] = state
    success = client.post("/api/v1/auth/oidc/callback", json=callback)
    assert success.status_code == 200
    assert client.post("/api/v1/auth/oidc/callback", json=callback).status_code == 401


def test_secret_rotation_is_tenant_scoped_and_never_returned_or_audited(
    client: TestClient, session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    reference = f"vault://tenants/{TEST_ORG_ID}/integrations/wazuh"
    integration = IntegrationAccount(
        organization_id=TEST_ORG_ID,
        integration_type="wazuh",
        name="rotation-test",
        base_url="https://wazuh.example.test",
        credential_reference=reference,
    )
    session.add(integration)
    session.commit()
    store = FakeCredentialStore()
    monkeypatch.setattr("app.api.router.get_credential_store", lambda: store)
    secret = "must-never-leak"
    response = client.post(
        f"/api/v1/integrations/{integration.id}/rotate-secret",
        json={"credentials": {"username": "svc", "password": secret}},
    )
    assert response.status_code == 200
    assert secret not in response.text
    assert store.rotations[0][0] == TEST_ORG_ID
    audit = session.scalar(select(AuditLog).where(AuditLog.action == "integration.secret_rotated"))
    assert audit is not None
    assert secret not in json.dumps(audit.details)
    assert (
        client.post(
            f"/api/v1/integrations/{integration.id}/rotate-secret",
            headers=auth_headers(OTHER_USER_ID, OTHER_ORG_ID),
            json={"credentials": {"password": secret}},
        ).status_code
        == 404
    )


def test_emergency_revocation_only_affects_selected_tenant(session: Session) -> None:
    now = datetime.now(UTC)
    local = AuthSession(
        organization_id=TEST_ORG_ID,
        user_id=TEST_USER_ID,
        auth_method="oidc:entra",
        mfa_verified=True,
        expires_at=now + timedelta(hours=1),
        last_seen_at=now,
    )
    foreign = AuthSession(
        organization_id=OTHER_ORG_ID,
        user_id=OTHER_USER_ID,
        auth_method="oidc:entra",
        mfa_verified=True,
        expires_at=now + timedelta(hours=1),
        last_seen_at=now,
    )
    session.add_all([local, foreign])
    session.commit()
    result = revoke_access(session, TEST_ORG_ID, reason="test incident")
    assert result == {"sessions_revoked": 1, "identity_providers_disabled": 0}
    session.refresh(local)
    session.refresh(foreign)
    assert local.revoked_at is not None
    assert foreign.revoked_at is None
