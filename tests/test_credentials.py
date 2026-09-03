import json
import uuid

import pytest

from app.core.credentials import CredentialStoreError, EnvironmentCredentialStore
from app.core.security import sanitize

TEST_ORGANIZATION_ID = uuid.UUID("20000000-0000-0000-0000-000000000001")


def test_environment_credential_store(monkeypatch) -> None:
    monkeypatch.setenv("WAZUH_SECRET_REF", json.dumps({"username": "u", "password": "p"}))
    assert (
        EnvironmentCredentialStore().get(TEST_ORGANIZATION_ID, "WAZUH_SECRET_REF")["password"]
        == "p"
    )


def test_missing_credentials_do_not_reveal_reference(monkeypatch) -> None:
    monkeypatch.delenv("VERY_SECRET_REFERENCE", raising=False)
    with pytest.raises(CredentialStoreError) as exc:
        EnvironmentCredentialStore().get(TEST_ORGANIZATION_ID, "VERY_SECRET_REFERENCE")
    assert "VERY_SECRET_REFERENCE" not in str(exc.value)


def test_recursive_sanitization() -> None:
    result = sanitize(
        {
            "password": "secret",
            "nested": {"indexer_password": "hidden", "client_secret": "hidden"},
            "safe": "value",
        }
    )
    assert result == {
        "password": "[REDACTED]",
        "nested": {"indexer_password": "[REDACTED]", "client_secret": "[REDACTED]"},
        "safe": "value",
    }


def test_sanitize_redacts_jwt_embedded_in_log_text() -> None:
    token = ".".join(["eyJ" + "hbGciOiJSUzI1NiJ9", "eyJ" + "zdWIiOiJ3b3JrZXIifQ", "signature"])
    assert sanitize(f"args=('{token}',)") == "args=('[REDACTED]',)"
