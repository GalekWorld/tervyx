import uuid

from pydantic import BaseModel, ConfigDict, Field


class AlertGroupStatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: str = Field(pattern="^(open|investigating|resolved|false_positive)$")
    resolution_reason: str | None = Field(default=None, max_length=5000)


class AlertGroupAssignmentUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    assigned_to: uuid.UUID | None


class AlertGroupFeedbackUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    analyst_feedback: str = Field(min_length=1, max_length=5000)
