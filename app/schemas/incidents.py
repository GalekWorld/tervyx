import uuid

from pydantic import BaseModel, ConfigDict, Field


class IncidentStatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: str = Field(pattern="^(open|investigating|contained|resolved|false_positive|reopened)$")
    resolution: str | None = Field(default=None, max_length=5000)


class IncidentAssignmentUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    assigned_to: uuid.UUID | None


class IncidentResolutionUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: str = Field(pattern="^(resolved|false_positive)$")
    resolution: str = Field(min_length=1, max_length=5000)


class IncidentReopenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=1, max_length=5000)


class InvestigationStatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: str = Field(pattern="^(pending|in_progress|completed|closed)$")
