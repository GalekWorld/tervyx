import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class DetectionORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class DetectionRuleConfigurationUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool
    suppression_window_seconds: int = Field(ge=0, le=604800)
    configuration: dict[str, Any] = Field(default_factory=dict)


class DetectionRuleConfigurationRead(DetectionORMModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    rule_id: str
    version: int
    enabled: bool
    active: bool
    suppression_window_seconds: int
    configuration: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class DetectionRuleMetricRead(DetectionORMModel):
    organization_id: uuid.UUID
    rule_id: str
    executions: int
    matches: int
    alerts_created: int
    alerts_suppressed: int
    last_match: datetime | None
    updated_at: datetime
