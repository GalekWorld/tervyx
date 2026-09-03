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
    criticality: int = Field(ge=1, le=5)
    last_seen: datetime | None
    created_at: datetime
    identity_key: str
    enrolled_at: datetime | None
    revoked_at: datetime | None
    certificate_serial: str | None
    certificate_expires_at: datetime | None
    heartbeat_interval_seconds: int
    last_health: dict[str, Any]
    agent_version: str | None


class EndpointEnrollRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    endpoint_id: uuid.UUID
    certificate_serial: str | None = Field(default=None, max_length=255)
    certificate_expires_at: datetime | None = None


class EndpointEnrollResponse(BaseModel):
    endpoint_id: uuid.UUID
    organization_id: uuid.UUID
    identity_key: str
    enrollment_token: str


class EndpointHeartbeatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    health: dict[str, Any] = Field(default_factory=dict)
    agent_version: str | None = Field(default=None, max_length=100)
    certificate_serial: str | None = Field(default=None, max_length=255)


class SecurityEventRead(ORMModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    endpoint_id: uuid.UUID
    source: str
    external_id: str
    event_type: str
    severity: int
    occurred_at: datetime
    normalized_data: dict[str, Any]
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
    rule_id: str | None
    mitre_attack: list[dict[str, str]]
    evidence: dict[str, Any]
    rule_version: int | None
    correlation_key: str | None
    created_at: datetime


class AlertGroupRead(ORMModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    correlation_key: str
    first_seen: datetime
    last_seen: datetime
    severity: int = Field(ge=0, le=10)
    affected_endpoint_ids: list[str]
    affected_users: list[str]
    source_ips: list[str]
    destination_ips: list[str]
    mitre_attack: list[dict[str, str]]
    evidence_summary: dict[str, Any]
    status: str
    assigned_to: uuid.UUID | None
    resolution_reason: str | None
    analyst_feedback: str | None
    closed_at: datetime | None
    created_at: datetime
    updated_at: datetime
    alert_ids: list[uuid.UUID] = Field(default_factory=list)


class AlertGroupHistoryRead(ORMModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    alert_group_id: uuid.UUID
    actor_id: uuid.UUID | None
    action: str
    previous_status: str | None
    new_status: str | None
    details: dict[str, Any]
    created_at: datetime


class IncidentRead(ORMModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    title: str
    description: str | None
    severity: int
    priority: str
    status: str
    confidence: float
    occurred_at: datetime
    first_seen: datetime
    last_seen: datetime
    correlation_key: str | None
    affected_endpoint_ids: list[str]
    affected_users: list[str]
    source_ips: list[str]
    destination_ips: list[str]
    mitre_attack: list[dict[str, str]]
    evidence: dict[str, Any]
    timeline: list[dict[str, Any]]
    assigned_to: uuid.UUID | None
    resolution: str | None
    closed_at: datetime | None
    sla_due_at: datetime
    created_at: datetime
    alert_ids: list[uuid.UUID] = Field(default_factory=list)
    alert_group_ids: list[uuid.UUID] = Field(default_factory=list)


class IncidentHistoryRead(ORMModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    incident_id: uuid.UUID
    actor_id: uuid.UUID | None
    action: str
    previous_status: str | None
    new_status: str | None
    details: dict[str, Any]
    created_at: datetime


class IncidentEnrichmentRead(ORMModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    incident_id: uuid.UUID
    enrichment_type: str
    source_type: str
    source: str
    fingerprint: str
    data: dict[str, Any]
    observed_at: datetime
    last_observed_at: datetime
    created_at: datetime


class InvestigationRead(ORMModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    alert_id: uuid.UUID | None
    incident_id: uuid.UUID | None
    risk_score: int = Field(ge=0, le=100)
    classification: str
    confidence: float = Field(ge=0, le=1)
    evidence: list[dict[str, Any]]
    timeline: list[dict[str, Any]]
    explanation: str
    recommended_actions: list[dict[str, Any]]
    status: str
    created_at: datetime
