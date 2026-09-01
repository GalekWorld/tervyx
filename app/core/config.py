from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Autonomous SOC"
    app_env: str = "development"
    debug: bool = False
    database_url: str = "postgresql+psycopg://soc:soc@localhost:5432/soc"
    sql_echo: bool = False
    api_v1_prefix: str = Field(default="/api/v1", pattern=r"^/")
    celery_broker_url: str = "redis://localhost:6379/0"
    celery_result_backend: str = "redis://localhost:6379/1"
    wazuh_request_timeout_seconds: float = 15.0
    wazuh_max_retries: int = 3
    jwt_private_key_path: str = ""
    jwt_public_key_path: str = ""
    jwt_active_kid: str = ""
    jwt_verification_keys_json: str = "{}"
    jwt_issuer: str = "autonomous-soc"
    jwt_audience: str = "autonomous-soc-api"
    access_token_ttl_minutes: int = 30
    refresh_token_ttl_days: int = 14
    max_request_body_bytes: int = 1_048_576
    max_page_size: int = 200
    rate_limit_requests: int = 120
    rate_limit_window_seconds: int = 60
    rate_limit_enabled: bool = True
    allowed_hosts: str = "localhost,127.0.0.1,testserver"
    cors_origins: str = ""
    allow_private_integration_urls: bool = False
    integration_allowed_hosts: str = ""
    integration_allowed_private_cidrs: str = ""
    otel_exporter_otlp_endpoint: str = ""
    sync_interval_seconds: int = 300
    credential_store_backend: str = "environment"

    @property
    def allowed_hosts_list(self) -> list[str]:
        return [item.strip() for item in self.allowed_hosts.split(",") if item.strip()]

    @property
    def cors_origins_list(self) -> list[str]:
        return [item.strip() for item in self.cors_origins.split(",") if item.strip()]

    @property
    def integration_allowed_hosts_list(self) -> list[str]:
        return [item.strip().lower() for item in self.integration_allowed_hosts.split(",") if item]

    @property
    def integration_private_networks(self) -> list[str]:
        return [item.strip() for item in self.integration_allowed_private_cidrs.split(",") if item]

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
