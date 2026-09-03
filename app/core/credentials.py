import json
import os
import uuid
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from app.core.config import get_settings


class CredentialStoreError(RuntimeError):
    pass


def _tenant_secret_name(organization_id: uuid.UUID, reference: str, scheme: str) -> str:
    prefix = f"{scheme}://"
    if not reference.startswith(prefix):
        raise CredentialStoreError("Credential reference uses the wrong provider scheme")
    name = reference.removeprefix(prefix).strip("/")
    expected = f"tenants/{organization_id}/"
    if not name.startswith(expected) or name == expected.rstrip("/"):
        raise CredentialStoreError("Credential reference is outside the tenant namespace")
    return name


def _json_object(raw: Any, message: str) -> dict[str, Any]:
    try:
        value = json.loads(raw) if isinstance(raw, str) else raw
    except json.JSONDecodeError as exc:
        raise CredentialStoreError(message) from exc
    if not isinstance(value, dict):
        raise CredentialStoreError(message)
    return value


class CredentialStore(ABC):
    @abstractmethod
    def get(self, organization_id: uuid.UUID, reference: str) -> dict[str, Any]: ...

    @abstractmethod
    def rotate(self, organization_id: uuid.UUID, reference: str, value: dict[str, Any]) -> str: ...


class EnvironmentCredentialStore(CredentialStore):
    """Development-only store backed by JSON environment variables."""

    def get(self, organization_id: uuid.UUID, reference: str) -> dict[str, Any]:
        del organization_id
        variable = reference.removeprefix("env://")
        raw = os.getenv(variable)
        if raw is None:
            raise CredentialStoreError("Credential reference is not configured")
        return _json_object(raw, "Credential reference contains invalid JSON")

    def rotate(self, organization_id: uuid.UUID, reference: str, value: dict[str, Any]) -> str:
        del organization_id, reference, value
        raise CredentialStoreError("Environment credentials cannot be rotated through the API")


class VaultCredentialStore(CredentialStore):
    """Vault KV v2 store using a strict per-tenant namespace."""

    scheme = "vault"
    address_variable = "VAULT_ADDR"
    authentication_variable = "VAULT_TOKEN"
    authentication_file_variable = "VAULT_TOKEN_FILE"

    def _client(self):
        try:
            import hvac
        except ImportError as exc:
            raise CredentialStoreError("Vault provider is not installed") from exc
        address = os.environ.get(self.address_variable)
        if get_settings().app_env == "production" and (
            not address or not address.startswith("https://")
        ):
            raise CredentialStoreError("Secrets manager must use HTTPS in production")
        token = os.environ.get(self.authentication_variable)
        token_file = os.environ.get(self.authentication_file_variable)
        if not token and token_file:
            try:
                token = Path(token_file).read_text(encoding="utf-8").strip()
            except OSError as exc:
                raise CredentialStoreError("Secrets manager authentication failed") from exc
        client = hvac.Client(url=address, token=token)
        if not client.is_authenticated():
            raise CredentialStoreError("Secrets manager authentication failed")
        return client

    def get(self, organization_id: uuid.UUID, reference: str) -> dict[str, Any]:
        path = _tenant_secret_name(organization_id, reference, self.scheme)
        try:
            value = self._client().secrets.kv.v2.read_secret_version(
                path=path, raise_on_deleted_version=True
            )["data"]["data"]
        except Exception as exc:
            raise CredentialStoreError("Secret could not be read") from exc
        return _json_object(value, "Secrets manager value must be a JSON object")

    def rotate(self, organization_id: uuid.UUID, reference: str, value: dict[str, Any]) -> str:
        path = _tenant_secret_name(organization_id, reference, self.scheme)
        try:
            result = self._client().secrets.kv.v2.create_or_update_secret(
                path=path, secret=dict(value)
            )
            version = result.get("data", {}).get("version")
        except Exception as exc:
            raise CredentialStoreError("Secret rotation failed") from exc
        return str(version or "created")


class OpenBaoCredentialStore(VaultCredentialStore):
    """OpenBao KV v2 adapter using the Vault-compatible API."""

    scheme = "openbao"
    address_variable = "OPENBAO_ADDR"
    authentication_variable = "OPENBAO_TOKEN"
    authentication_file_variable = "OPENBAO_TOKEN_FILE"


class AWSSecretsManagerCredentialStore(CredentialStore):
    """AWS Secrets Manager using its workload credential provider chain."""

    def __init__(self, client: Any | None = None) -> None:
        self._provided_client = client

    def _client(self):
        if self._provided_client is not None:
            return self._provided_client
        try:
            import boto3
        except ImportError as exc:
            raise CredentialStoreError("AWS Secrets Manager provider is not installed") from exc
        return boto3.client("secretsmanager")

    def get(self, organization_id: uuid.UUID, reference: str) -> dict[str, Any]:
        secret_id = _tenant_secret_name(organization_id, reference, "aws-sm")
        try:
            raw = self._client().get_secret_value(SecretId=secret_id).get("SecretString")
        except Exception as exc:
            raise CredentialStoreError("Secret could not be read") from exc
        return _json_object(raw, "AWS secret must contain a JSON object")

    def rotate(self, organization_id: uuid.UUID, reference: str, value: dict[str, Any]) -> str:
        secret_id = _tenant_secret_name(organization_id, reference, "aws-sm")
        try:
            result = self._client().put_secret_value(
                SecretId=secret_id,
                SecretString=json.dumps(value, separators=(",", ":")),
                VersionStages=["AWSCURRENT"],
            )
        except Exception as exc:
            raise CredentialStoreError("Secret rotation failed") from exc
        return str(result.get("VersionId") or "created")


def get_credential_store() -> CredentialStore:
    providers: dict[str, type[CredentialStore]] = {
        "environment": EnvironmentCredentialStore,
        "vault": VaultCredentialStore,
        "openbao": OpenBaoCredentialStore,
        "aws_secrets_manager": AWSSecretsManagerCredentialStore,
    }
    settings = get_settings()
    if settings.app_env == "production" and settings.credential_store_backend == "environment":
        raise CredentialStoreError("Environment credential store is disabled in production")
    try:
        return providers[settings.credential_store_backend]()
    except KeyError as exc:
        raise CredentialStoreError("Unsupported credential store backend") from exc
