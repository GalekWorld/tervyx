import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class DeadLetterRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    organization_id: uuid.UUID
    integration_account_id: uuid.UUID
    payload: dict[str, Any]
    error: str
    attempts: int
    first_failed_at: datetime
    last_failed_at: datetime
    status: str
    created_at: datetime
    updated_at: datetime
