import os
import uuid

import hvac
import pytest

from app.core.credentials import OpenBaoCredentialStore, VaultCredentialStore

pytestmark = pytest.mark.integration


def test_vault_kv_v2_real_round_trip(monkeypatch) -> None:
    address = os.getenv("INTEGRATION_VAULT_ADDR")
    token = os.getenv("INTEGRATION_VAULT_TOKEN")
    if not address or not token:
        pytest.skip("INTEGRATION_VAULT_ADDR/token are not configured")
    organization_id = uuid.uuid4()
    path = f"tenants/{organization_id}/soc-tests/{uuid.uuid4()}"
    client = hvac.Client(url=address, token=token)
    assert client.is_authenticated()
    expected = {"username": "reader", "password": "not-logged", "verify_ssl": True}
    client.secrets.kv.v2.create_or_update_secret(path=path, secret=expected)
    monkeypatch.setenv("VAULT_ADDR", address)
    monkeypatch.setenv("VAULT_TOKEN", token)
    store = VaultCredentialStore()
    assert store.get(organization_id, f"vault://{path}") == expected
    version = store.rotate(
        organization_id,
        f"vault://{path}",
        {**expected, "password": "rotated-not-logged"},
    )
    assert version
    assert store.get(organization_id, f"vault://{path}")["password"] == "rotated-not-logged"
    client.secrets.kv.v2.delete_metadata_and_all_versions(path=path)


def test_openbao_kv_v2_real_round_trip(monkeypatch) -> None:
    address = os.getenv("INTEGRATION_OPENBAO_ADDR")
    token = os.getenv("INTEGRATION_OPENBAO_TOKEN")
    if not address or not token:
        pytest.skip("INTEGRATION_OPENBAO_ADDR/token are not configured")
    organization_id = uuid.uuid4()
    path = f"tenants/{organization_id}/soc-tests/{uuid.uuid4()}"
    client = hvac.Client(url=address, token=token)
    assert client.is_authenticated()
    expected = {"client_secret": "not-logged"}
    client.secrets.kv.v2.create_or_update_secret(path=path, secret=expected)
    monkeypatch.setenv("OPENBAO_ADDR", address)
    monkeypatch.setenv("OPENBAO_TOKEN", token)
    store = OpenBaoCredentialStore()
    reference = f"openbao://{path}"
    assert store.get(organization_id, reference) == expected
    assert store.rotate(organization_id, reference, {"client_secret": "rotated"})
    assert store.get(organization_id, reference) == {"client_secret": "rotated"}
    client.secrets.kv.v2.delete_metadata_and_all_versions(path=path)
