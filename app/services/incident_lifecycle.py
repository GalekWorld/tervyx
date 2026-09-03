"""Auditable lifecycle operations for tenant-scoped incidents."""

import uuid
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.models import Incident, IncidentHistory

VALID_TRANSITIONS = {
    "open": {"investigating", "contained", "resolved", "false_positive"},
    "investigating": {"open", "contained", "resolved", "false_positive"},
    "contained": {"investigating", "resolved", "false_positive"},
    "resolved": {"reopened"},
    "false_positive": {"reopened"},
    "reopened": {"investigating", "contained", "resolved", "false_positive"},
}
CLOSED_STATUSES = {"resolved", "false_positive"}


class InvalidIncidentTransition(ValueError):
    pass


class IncidentLifecycleService:
    def __init__(self, session: Session, organization_id: uuid.UUID) -> None:
        self.session = session
        self.organization_id = organization_id

    def transition(
        self,
        incident: Incident,
        actor_id: uuid.UUID,
        new_status: str,
        resolution: str | None = None,
    ) -> None:
        self._validate(incident)
        if new_status not in VALID_TRANSITIONS.get(incident.status, set()):
            raise InvalidIncidentTransition(
                f"Invalid transition: {incident.status} -> {new_status}"
            )
        if new_status in CLOSED_STATUSES and not resolution:
            raise InvalidIncidentTransition("A resolution is required when closing an incident")
        previous_status = incident.status
        incident.status = new_status
        if new_status in CLOSED_STATUSES:
            incident.resolution = resolution
            incident.closed_at = datetime.now(UTC)
        elif new_status == "reopened":
            incident.closed_at = None
            incident.resolution = None
        self._history(
            incident,
            actor_id,
            "status_changed",
            previous_status,
            new_status,
            {"resolution": resolution} if resolution else {},
        )

    def assign(
        self, incident: Incident, actor_id: uuid.UUID, assigned_to: uuid.UUID | None
    ) -> None:
        self._validate(incident)
        previous = incident.assigned_to
        incident.assigned_to = assigned_to
        self._history(
            incident,
            actor_id,
            "assigned",
            None,
            None,
            {
                "previous_assigned_to": str(previous) if previous else None,
                "assigned_to": str(assigned_to) if assigned_to else None,
            },
        )

    def reopen(self, incident: Incident, actor_id: uuid.UUID, reason: str) -> None:
        self.transition(incident, actor_id, "reopened")
        self._history(incident, actor_id, "reopened", None, None, {"reason": reason})

    def _validate(self, incident: Incident) -> None:
        if incident.organization_id != self.organization_id:
            raise ValueError("Incident organization does not match lifecycle tenant")

    def _history(
        self,
        incident: Incident,
        actor_id: uuid.UUID,
        action: str,
        previous_status: str | None,
        new_status: str | None,
        details: dict[str, str | None],
    ) -> None:
        self.session.add(
            IncidentHistory(
                organization_id=self.organization_id,
                incident_id=incident.id,
                actor_id=actor_id,
                action=action,
                previous_status=previous_status,
                new_status=new_status,
                details=details,
            )
        )
