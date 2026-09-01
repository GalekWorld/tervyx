import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.network import validate_outbound_url


class IntegrationCreate(BaseModel):
    integration_type: str = Field(pattern="^wazuh$")
    name: str = Field(min_length=1, max_length=255)
    base_url: str = Field(min_length=8, max_length=2048)
    credential_reference: str = Field(min_length=1, max_length=255)
    enabled: bool = True

    @field_validator("base_url")
    @classmethod
    def secure_url(cls, value: str) -> str:
        return validate_outbound_url(value)


class IntegrationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    organization_id: uuid.UUID
    integration_type: str
    name: str
    base_url: str
    enabled: bool
    status: str
    last_success_at: datetime | None
    last_error_at: datetime | None
    last_error: str | None
    created_at: datetime
    updated_at: datetime


class IntegrationStatus(IntegrationRead):
    checkpoints: list[dict] = Field(default_factory=list)


class JobAccepted(BaseModel):
    job_id: str
    status: str = "queued"


class ConnectionTestResult(BaseModel):
    ok: bool
    detail: str


class Page(BaseModel):
    items: list
    page: int
    page_size: int
    total: int
