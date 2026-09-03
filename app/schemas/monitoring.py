import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class SecuritySignalRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    signal_type: str
    severity: str
    evidence: dict[str, Any]
    source_action: str
    actor_id: str | None
    first_seen_at: datetime
    last_seen_at: datetime
    occurrences: int
    status: str
