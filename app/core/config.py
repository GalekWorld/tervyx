from functools import lru_cache

from pydantic import Field, model_validator
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
    session_ttl_hours: int = 12
    oidc_transaction_ttl_minutes: int = 10
    oidc_transaction_key: str = ""
    oidc_http_timeout_seconds: float = 10.0
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
    otel_metrics_export_interval_seconds: int = Field(default=600, ge=15, le=3600)
    sentry_dsn: str = ""
    sentry_environment: str = ""
    sentry_release: str = ""
    sentry_traces_sample_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    sync_interval_seconds: int = 300
    credential_store_backend: str = "environment"
    ingestion_batch_size: int = 500
    alert_correlation_window_seconds: int = Field(default=3600, ge=1, le=604800)
    incident_sla_hours: int = Field(default=24, ge=1, le=720)
    tenant_default_max_events_per_day: int = 100_000
    tenant_default_max_jobs_per_minute: int = 1_000
    tenant_default_max_api_requests_per_minute: int = 1_000
    tenant_default_max_storage_bytes: int = 10 * 1024 * 1024 * 1024
    tenant_default_max_queue_depth: int = 5_000
    tenant_fair_dispatch_batch_size: int = 64
    retention_default_days: int = 90
    audit_ledger_retention_days: int = Field(default=2555, ge=1, le=36500)
    retention_archive_after_days: int = 30
    archive_batch_size: int = 1_000
    object_storage_backend: str = "filesystem"
    object_storage_bucket: str = "tervyx-archive"
    object_storage_prefix: str = "tervyx"
    object_storage_endpoint_url: str = ""
    object_storage_region: str = "eu-west-1"
    object_storage_local_path: str = "/tmp/tervyx-archive"  # noqa: S108 - configurable dev store
    backup_s3_bucket: str = "tervyx-backups"
    backup_s3_prefix: str = "postgres"
    pitr_enabled: bool = False

    @model_validator(mode="after")
    def validate_production_security(self) -> "Settings":
        """Fail closed for unsafe defaults when starting a production process."""
        if self.app_env.lower() != "production":
            return self
        if self.debug or not self.rate_limit_enabled:
            raise ValueError("debug and disabled rate limiting are forbidden in production")
        if self.credential_store_backend.lower() == "environment":
            raise ValueError("production requires an external credential store")
        if not self.jwt_private_key_path or not self.jwt_public_key_path or not self.jwt_active_kid:
            raise ValueError("production requires JWT signing keys and an active kid")
        if not self.oidc_transaction_key:
            raise ValueError("production requires OIDC_TRANSACTION_KEY")
        if "*" in self.allowed_hosts or "*" in self.cors_origins:
            raise ValueError("wildcard hosts/origins are forbidden in production")
        if "localhost" in self.database_url or "soc:soc@" in self.database_url:
            raise ValueError("production database URL must not use local defaults")
        if not self.sentry_dsn or not self.sentry_dsn.startswith("https://"):
            raise ValueError("production requires an HTTPS Sentry DSN")
        if not self.otel_exporter_otlp_endpoint or not self.otel_exporter_otlp_endpoint.startswith(
            "https://"
        ):
            raise ValueError("production requires an HTTPS OTLP endpoint")
        if "sslmode=verify-full" not in self.database_url:
            raise ValueError("production PostgreSQL must use sslmode=verify-full")
        if self.celery_broker_url.startswith("redis://") or self.celery_result_backend.startswith(
            "redis://"
        ):
            raise ValueError("production Redis endpoints must use TLS (rediss://)")
        return self

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
