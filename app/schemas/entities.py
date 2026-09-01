import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class EndpointRead(ORMModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    hostname: str
    operating_system: str | None
    ip_address: str | None
    agent_id: str
    status: str
    last_seen: datetime | None
    created_at: datetime


class SecurityEventRead(ORMModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    endpoint_id: uuid.UUID
    source: str
    external_id: str
    event_type: str
    severity: int
    occurred_at: datetime
    created_at: datetime


class AlertRead(ORMModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    endpoint_id: uuid.UUID
    source: str
    external_id: str
    title: str
    description: str | None
    severity: int = Field(ge=0, le=10)
    status: str
    occurred_at: datetime
    created_at: datetime


class IncidentRead(ORMModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    title: str
    description: str | None
    severity: int
    status: str
    occurred_at: datetime
    created_at: datetime
    alert_ids: list[uuid.UUID] = Field(default_factory=list)


class InvestigationRead(ORMModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    alert_id: uuid.UUID | None
    incident_id: uuid.UUID | None
    risk_score: int = Field(ge=0, le=100)
    classification: str
    confidence: float = Field(ge=0, le=1)
    evidence: list[dict[str, Any]]
    explanation: str
    recommended_actions: list[dict[str, Any]]
    status: str
    created_at: datetime
