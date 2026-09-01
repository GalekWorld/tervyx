from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Any


class AdapterError(ValueError):
    """Raised when a provider payload cannot be normalized."""


@dataclass(frozen=True, slots=True)
class NormalizedEndpoint:
    agent_id: str
    hostname: str
    operating_system: str | None
    ip_address: str | None
    status: str
    last_seen: datetime


@dataclass(frozen=True, slots=True)
class NormalizedEvent:
    external_id: str
    event_type: str
    severity: int
    occurred_at: datetime
    raw_payload: dict[str, Any]


@dataclass(frozen=True, slots=True)
class NormalizedAlert:
    external_id: str
    title: str
    description: str | None
    severity: int
    status: str
    occurred_at: datetime


@dataclass(frozen=True, slots=True)
class NormalizedSecurityRecord:
    source: str
    endpoint: NormalizedEndpoint
    event: NormalizedEvent
    alert: NormalizedAlert | None


class SecuritySourceAdapter(ABC):
    source: str

    @abstractmethod
    def normalize(self, payload: dict[str, Any]) -> NormalizedSecurityRecord:
        """Convert a provider payload into the provider-neutral internal contract."""
