import socket
import uuid

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.auth import create_access_token, create_worker_token, hash_password
from app.core.config import Settings, get_settings
from app.core.network import UnsafeURLError, validate_outbound_url
from app.models import User
from tests.conftest import TEST_ORG_ID, auth_headers


def add_user(session: Session, role: str) -> User:
    user = User(
        organization_id=TEST_ORG_ID,
        email=f"{role}@test.local",
        display_name=role,
        role=role,
        password_hash=hash_password("secure-password"),
    )
    session.add(user)
    session.commit()
    return user


def test_login_and_manipulated_jwt(client: TestClient) -> None:
    response = client.post(
        "/api/v1/auth/token",
        json={
            "organization_slug": "test-org",
            "email": "admin@test.local",
            "password": "test-password",
        },
    )
    assert response.status_code == 200
    token = response.json()["access_token"]
    assert jwt.get_unverified_header(token) == {"alg": "RS256", "kid": "test-key-1", "typ": "JWT"}
    parts = token.split(".")
    manipulated = f"{parts[0]}.{parts[1]}.{parts[2][::-1]}"
    assert (
        client.get(
            "/api/v1/endpoints", headers={"Authorization": f"Bearer {manipulated}"}
        ).status_code
        == 401
    )


def test_jwks_refresh_rotation_and_revocation(client: TestClient) -> None:
    login = client.post(
        "/api/v1/auth/token",
        json={
            "organization_slug": "test-org",
            "email": "admin@test.local",
            "password": "test-password",
        },
    )
    first_refresh = login.json()["refresh_token"]
    jwks = client.get("/.well-known/jwks.json")
    assert jwks.status_code == 200
    assert jwks.json()["keys"][0]["kid"] == "test-key-1"

    rotated = client.post("/api/v1/auth/refresh", json={"refresh_token": first_refresh})
    assert rotated.status_code == 200
    second_refresh = rotated.json()["refresh_token"]
    assert second_refresh != first_refresh
    assert (
        client.post("/api/v1/auth/refresh", json={"refresh_token": first_refresh}).status_code
        == 401
    )
    assert (
        client.post("/api/v1/auth/revoke", json={"refresh_token": second_refresh}).status_code
        == 204
    )
    assert (
        client.post("/api/v1/auth/refresh", json={"refresh_token": second_refresh}).status_code
        == 401
    )


def test_roles_enforced(client: TestClient, session: Session) -> None:
    viewer = add_user(session, "viewer")
    analyst = add_user(session, "analyst")
    integration = {
        "integration_type": "wazuh",
        "name": "Forbidden",
        "base_url": "https://127.0.0.1:55000",
        "credential_reference": "TEST",
    }
    assert (
        client.get(
            "/api/v1/endpoints", headers=auth_headers(viewer.id, TEST_ORG_ID, "viewer")
        ).status_code
        == 200
    )
    assert (
        client.post(
            "/api/v1/integrations",
            json=integration,
            headers=auth_headers(viewer.id, TEST_ORG_ID, "viewer"),
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/v1/integrations",
            json=integration,
            headers=auth_headers(analyst.id, TEST_ORG_ID, "analyst"),
        ).status_code
        == 403
    )


def test_token_with_stale_role_is_rejected(client: TestClient, session: Session) -> None:
    viewer = add_user(session, "viewer")
    token = create_access_token(viewer.id, TEST_ORG_ID, "admin")
    assert (
        client.get("/api/v1/endpoints", headers={"Authorization": f"Bearer {token}"}).status_code
        == 401
    )


def test_ssrf_blocks_private_dns(monkeypatch) -> None:
    settings = get_settings()
    old = settings.allow_private_integration_urls
    settings.allow_private_integration_urls = False
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *args: [(socket.AF_INET, 0, 0, "", ("169.254.169.254", 443))]
    )
    try:
        try:
            validate_outbound_url("https://metadata.example/latest")
            assert False, "private address accepted"
        except UnsafeURLError:
            pass
    finally:
        settings.allow_private_integration_urls = old


def test_ssrf_blocks_mixed_dns_answers_used_for_rebinding(monkeypatch) -> None:
    settings = get_settings()
    old = settings.allow_private_integration_urls
    settings.allow_private_integration_urls = False
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args: [
            (socket.AF_INET, 0, 0, "", ("93.184.216.34", 443)),
            (socket.AF_INET, 0, 0, "", ("127.0.0.1", 443)),
        ],
    )
    try:
        with pytest.raises(UnsafeURLError):
            validate_outbound_url("https://rebind.example/api")
    finally:
        settings.allow_private_integration_urls = old


def test_worker_jwt_cannot_be_replayed_against_api(client: TestClient) -> None:
    token = create_worker_token(TEST_ORG_ID, uuid.uuid4())
    response = client.get("/api/v1/endpoints", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_payload_and_pagination_limits(client: TestClient) -> None:
    too_large = {"source": "wazuh", "payload": {"blob": "x" * 1_048_576}}
    assert client.post("/api/v1/events", json=too_large).status_code == 413
    assert client.get("/api/v1/events?page_size=501").status_code == 422


def test_rate_limit_returns_429_and_retry_after(client: TestClient, monkeypatch) -> None:
    class FakeRedis:
        count = 0

        def incr(self, _key):
            self.__class__.count += 1
            return self.__class__.count

        def expire(self, _key, _seconds):
            return True

    settings = get_settings()
    old_enabled = settings.rate_limit_enabled
    old_requests = settings.rate_limit_requests
    settings.rate_limit_enabled = True
    settings.rate_limit_requests = 1
    monkeypatch.setattr("app.core.middleware.Redis.from_url", lambda _url: FakeRedis())
    try:
        assert client.get("/api/v1/endpoints").status_code == 200
        response = client.get("/api/v1/endpoints")
        assert response.status_code == 429
        assert response.headers["Retry-After"] == str(settings.rate_limit_window_seconds)
    finally:
        settings.rate_limit_enabled = old_enabled
        settings.rate_limit_requests = old_requests


def test_production_settings_fail_closed_on_local_defaults() -> None:
    with pytest.raises(ValueError, match="production"):
        Settings(app_env="production")
