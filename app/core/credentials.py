import json
import os
from abc import ABC, abstractmethod
from typing import Any


class CredentialStoreError(RuntimeError):
    pass


class CredentialStore(ABC):
    @abstractmethod
    def get(self, reference: str) -> dict[str, Any]: ...


class EnvironmentCredentialStore(CredentialStore):
    """Development store: references an environment variable containing JSON."""

    def get(self, reference: str) -> dict[str, Any]:
        variable = reference.removeprefix("env://")
        raw = os.getenv(variable)
        if raw is None:
            raise CredentialStoreError("Credential reference is not configured")
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise CredentialStoreError("Credential reference contains invalid JSON") from exc
        if not isinstance(value, dict):
            raise CredentialStoreError("Credential value must be a JSON object")
        return value


class VaultCredentialStore(CredentialStore):
    """Vault KV v2 adapter. The optional `hvac` dependency is loaded lazily."""

    def get(self, reference: str) -> dict[str, Any]:
        try:
            import hvac  # type: ignore[import-not-found]
        except ImportError as exc:
            raise CredentialStoreError("Vault provider is not installed") from exc
        path = reference.removeprefix("vault://")
        client = hvac.Client(url=os.environ.get("VAULT_ADDR"), token=os.environ.get("VAULT_TOKEN"))
        if not client.is_authenticated():
            raise CredentialStoreError("Vault authentication failed")
        value = client.secrets.kv.v2.read_secret_version(path=path, raise_on_deleted_version=True)[
            "data"
        ]["data"]
        if not isinstance(value, dict):
            raise CredentialStoreError("Vault secret must be an object")
        return value


class AWSSecretsManagerCredentialStore(CredentialStore):
    """AWS Secrets Manager adapter; credentials follow the normal AWS provider chain."""

    def get(self, reference: str) -> dict[str, Any]:
        try:
            import boto3  # type: ignore[import-not-found]
        except ImportError as exc:
            raise CredentialStoreError("AWS Secrets Manager provider is not installed") from exc
        secret_id = reference.removeprefix("aws-sm://")
        raw = boto3.client("secretsmanager").get_secret_value(SecretId=secret_id)["SecretString"]
        try:
            value = json.loads(raw)
        except (json.JSONDecodeError, TypeError) as exc:
            raise CredentialStoreError("AWS secret contains invalid JSON") from exc
        if not isinstance(value, dict):
            raise CredentialStoreError("AWS secret must be an object")
        return value


def get_credential_store() -> CredentialStore:
    from app.core.config import get_settings

    providers: dict[str, type[CredentialStore]] = {
        "environment": EnvironmentCredentialStore,
        "vault": VaultCredentialStore,
        "aws_secrets_manager": AWSSecretsManagerCredentialStore,
    }
    settings = get_settings()
    if settings.app_env == "production" and settings.credential_store_backend == "environment":
        raise CredentialStoreError("Environment credential store is disabled in production")
    try:
        return providers[settings.credential_store_backend]()
    except KeyError as exc:
        raise CredentialStoreError("Unsupported credential store backend") from exc
