import os
import uuid

import hvac
import pytest

from app.core.credentials import VaultCredentialStore

pytestmark = pytest.mark.integration


def test_vault_kv_v2_real_round_trip(monkeypatch) -> None:
    address = os.getenv("INTEGRATION_VAULT_ADDR")
    token = os.getenv("INTEGRATION_VAULT_TOKEN")
    if not address or not token:
        pytest.skip("INTEGRATION_VAULT_ADDR/token are not configured")
    path = f"soc-tests/{uuid.uuid4()}"
    client = hvac.Client(url=address, token=token)
    assert client.is_authenticated()
    expected = {"username": "reader", "password": "not-logged", "verify_ssl": True}
    client.secrets.kv.v2.create_or_update_secret(path=path, secret=expected)
    monkeypatch.setenv("VAULT_ADDR", address)
    monkeypatch.setenv("VAULT_TOKEN", token)
    assert VaultCredentialStore().get(f"vault://{path}") == expected
    client.secrets.kv.v2.delete_metadata_and_all_versions(path=path)
