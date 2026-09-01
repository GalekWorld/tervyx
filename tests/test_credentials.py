import json

import pytest

from app.core.credentials import CredentialStoreError, EnvironmentCredentialStore
from app.core.security import sanitize


def test_environment_credential_store(monkeypatch) -> None:
    monkeypatch.setenv("WAZUH_SECRET_REF", json.dumps({"username": "u", "password": "p"}))
    assert EnvironmentCredentialStore().get("WAZUH_SECRET_REF")["password"] == "p"


def test_missing_credentials_do_not_reveal_reference(monkeypatch) -> None:
    monkeypatch.delenv("VERY_SECRET_REFERENCE", raising=False)
    with pytest.raises(CredentialStoreError) as exc:
        EnvironmentCredentialStore().get("VERY_SECRET_REFERENCE")
    assert "VERY_SECRET_REFERENCE" not in str(exc.value)


def test_recursive_sanitization() -> None:
    result = sanitize({"password": "secret", "nested": {"token": "jwt"}, "safe": "value"})
    assert result == {"password": "[REDACTED]", "nested": {"token": "[REDACTED]"}, "safe": "value"}
