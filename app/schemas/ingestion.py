import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.entities import AlertRead, EndpointRead, SecurityEventRead


class EventIngestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: str = Field(default="wazuh", min_length=1, max_length=50)
    payload: dict[str, Any]


class IngestResult(BaseModel):
    endpoint: EndpointRead
    event: SecurityEventRead
    alert: AlertRead | None
    duplicate: bool = False
    organization_id: uuid.UUID
