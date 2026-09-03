import base64
import os
import tempfile
import uuid
from collections.abc import Generator

os.environ["DATABASE_URL"] = "sqlite://"
os.environ["APP_ENV"] = "test"
os.environ["RATE_LIMIT_ENABLED"] = "false"
os.environ["ALLOW_PRIVATE_INTEGRATION_URLS"] = "true"
os.environ["OIDC_TRANSACTION_KEY"] = base64.urlsafe_b64encode(os.urandom(32)).decode()

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

_jwt_directory = tempfile.mkdtemp(prefix="soc-test-jwt-")
_jwt_private_path = os.path.join(_jwt_directory, "private.pem")
_jwt_public_path = os.path.join(_jwt_directory, "public.pem")
_jwt_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
with open(_jwt_private_path, "wb") as _private_file:
    _private_file.write(
        _jwt_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
with open(_jwt_public_path, "wb") as _public_file:
    _public_file.write(
        _jwt_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
os.environ["JWT_PRIVATE_KEY_PATH"] = _jwt_private_path
os.environ["JWT_PUBLIC_KEY_PATH"] = _jwt_public_path
os.environ["JWT_ACTIVE_KID"] = "test-key-1"

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.auth import create_access_token, hash_password
from app.core.database import Base, get_db
from app.main import create_app
from app.models import Endpoint, Organization, User

TEST_ORG_ID = uuid.UUID("20000000-0000-0000-0000-000000000001")
OTHER_ORG_ID = uuid.UUID("20000000-0000-0000-0000-000000000002")
TEST_USER_ID = uuid.UUID("30000000-0000-0000-0000-000000000001")
OTHER_USER_ID = uuid.UUID("30000000-0000-0000-0000-000000000002")


@pytest.fixture()
def session() -> Generator[Session, None, None]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    db = factory()
    db.add_all(
        [
            Organization(id=TEST_ORG_ID, name="Test Org", slug="test-org"),
            Organization(id=OTHER_ORG_ID, name="Other Org", slug="other-org"),
        ]
    )
    db.commit()
    db.add_all(
        [
            User(
                id=TEST_USER_ID,
                organization_id=TEST_ORG_ID,
                email="admin@test.local",
                display_name="Admin",
                role="admin",
                password_hash=hash_password("test-password"),
            ),
            User(
                id=OTHER_USER_ID,
                organization_id=OTHER_ORG_ID,
                email="admin@other.local",
                display_name="Other Admin",
                role="admin",
                password_hash=hash_password("test-password"),
            ),
        ]
    )
    db.commit()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(engine)
        engine.dispose()


@pytest.fixture()
def client(session: Session) -> Generator[TestClient, None, None]:
    application = create_app()

    def override_get_db():
        yield session

    application.dependency_overrides[get_db] = override_get_db
    token = create_access_token(TEST_USER_ID, TEST_ORG_ID, "admin")
    with TestClient(application, headers={"Authorization": f"Bearer {token}"}) as test_client:
        yield test_client


def auth_headers(user_id=TEST_USER_ID, organization_id=TEST_ORG_ID, role="admin") -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token(user_id, organization_id, role)}"}


@pytest.fixture()
def endpoint(session: Session) -> Endpoint:
    entity = Endpoint(
        organization_id=TEST_ORG_ID,
        hostname="host-01",
        operating_system="Ubuntu 24.04",
        ip_address="10.0.0.10",
        agent_id="agent-01",
        status="active",
    )
    session.add(entity)
    session.commit()
    return entity


@pytest.fixture()
def wazuh_payload() -> dict:
    return {
        "id": "wazuh-1700000000.123",
        "timestamp": "2026-08-31T08:30:00.000Z",
        "agent": {
            "id": "wazuh-agent-007",
            "name": "finance-laptop",
            "ip": "10.0.0.27",
            "os": {"name": "Windows 11"},
        },
        "rule": {
            "id": "5710",
            "level": 12,
            "description": "Multiple authentication failures",
            "groups": ["authentication_failed", "sshd"],
        },
        "full_log": "Failed password for invalid user admin",
    }
