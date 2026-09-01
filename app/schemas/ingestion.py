import uuid
from typing import Any

from pydantic import BaseModel, Field

from app.schemas.entities import AlertRead, EndpointRead, SecurityEventRead


class EventIngestRequest(BaseModel):
    source: str = Field(default="wazuh", min_length=1, max_length=50)
    payload: dict[str, Any]


class IngestResult(BaseModel):
    endpoint: EndpointRead
    event: SecurityEventRead
    alert: AlertRead | None
    duplicate: bool = False
    organization_id: uuid.UUID
