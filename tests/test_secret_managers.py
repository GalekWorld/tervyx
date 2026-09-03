import json
import uuid

import pytest

from app.core.config import get_settings
from app.core.credentials import (
    AWSSecretsManagerCredentialStore,
    CredentialStoreError,
    OpenBaoCredentialStore,
    VaultCredentialStore,
    get_credential_store,
)


class FakeAWSClient:
    def __init__(self) -> None:
        self.secret_id: str | None = None
        self.value = json.dumps({"client_secret": "initial"})

    def get_secret_value(self, *, SecretId: str) -> dict:
        self.secret_id = SecretId
        return {"SecretString": self.value}

    def put_secret_value(
        self, *, SecretId: str, SecretString: str, VersionStages: list[str]
    ) -> dict:
        assert VersionStages == ["AWSCURRENT"]
        self.secret_id = SecretId
        self.value = SecretString
        return {"VersionId": "aws-version-2"}


@pytest.mark.parametrize(
    ("store", "scheme"),
    [(VaultCredentialStore(), "vault"), (OpenBaoCredentialStore(), "openbao")],
)
def test_vault_compatible_stores_reject_cross_tenant_references(store, scheme: str) -> None:
    organization_id = uuid.uuid4()
    other_id = uuid.uuid4()
    with pytest.raises(CredentialStoreError, match="tenant namespace"):
        store.get(
            organization_id,
            f"{scheme}://tenants/{other_id}/integrations/wazuh",
        )


def test_aws_secrets_manager_contract_and_rotation_are_tenant_scoped() -> None:
    organization_id = uuid.uuid4()
    other_id = uuid.uuid4()
    client = FakeAWSClient()
    store = AWSSecretsManagerCredentialStore(client)
    reference = f"aws-sm://tenants/{organization_id}/oidc/entra"
    assert store.get(organization_id, reference) == {"client_secret": "initial"}
    assert store.rotate(organization_id, reference, {"client_secret": "rotated"}) == "aws-version-2"
    assert client.secret_id == f"tenants/{organization_id}/oidc/entra"
    assert store.get(organization_id, reference) == {"client_secret": "rotated"}
    with pytest.raises(CredentialStoreError, match="tenant namespace"):
        store.rotate(
            organization_id,
            f"aws-sm://tenants/{other_id}/oidc/entra",
            {"client_secret": "attacker"},
        )


def test_environment_store_is_rejected_in_production(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = get_settings()
    monkeypatch.setattr(settings, "app_env", "production")
    monkeypatch.setattr(settings, "credential_store_backend", "environment")
    with pytest.raises(CredentialStoreError, match="disabled in production"):
        get_credential_store()


def test_vault_requires_tls_in_production(monkeypatch: pytest.MonkeyPatch) -> None:
    organization_id = uuid.uuid4()
    settings = get_settings()
    monkeypatch.setattr(settings, "app_env", "production")
    monkeypatch.setenv("VAULT_ADDR", "http://vault.internal:8200")
    monkeypatch.setenv("VAULT_TOKEN", "not-logged")
    with pytest.raises(CredentialStoreError):
        VaultCredentialStore().get(
            organization_id, f"vault://tenants/{organization_id}/integration/test"
        )
