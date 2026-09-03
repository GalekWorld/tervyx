"""Auditable lifecycle transitions for tenant-scoped alert groups."""

import uuid
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.models import AlertGroup, AlertGroupHistory

VALID_TRANSITIONS = {
    "open": {"investigating", "resolved", "false_positive"},
    "investigating": {"open", "resolved", "false_positive"},
    "resolved": set(),
    "false_positive": set(),
}
CLOSED_STATUSES = {"resolved", "false_positive"}


class InvalidAlertGroupTransition(ValueError):
    pass


class AlertGroupLifecycleService:
    def __init__(self, session: Session, organization_id: uuid.UUID) -> None:
        self.session = session
        self.organization_id = organization_id

    def transition(
        self,
        group: AlertGroup,
        actor_id: uuid.UUID,
        new_status: str,
        resolution_reason: str | None = None,
    ) -> None:
        self._validate_group(group)
        if new_status not in VALID_TRANSITIONS.get(group.status, set()):
            raise InvalidAlertGroupTransition(f"Invalid transition: {group.status} -> {new_status}")
        if new_status in CLOSED_STATUSES and not resolution_reason:
            raise InvalidAlertGroupTransition(
                "A resolution reason is required when closing an alert group"
            )
        previous_status = group.status
        group.status = new_status
        if new_status in CLOSED_STATUSES:
            group.closed_at = datetime.now(UTC)
            group.resolution_reason = resolution_reason
        self._history(
            group,
            actor_id,
            "status_changed",
            previous_status,
            new_status,
            {"resolution_reason": resolution_reason} if resolution_reason else {},
        )

    def assign(self, group: AlertGroup, actor_id: uuid.UUID, assigned_to: uuid.UUID | None) -> None:
        self._validate_group(group)
        previous = group.assigned_to
        group.assigned_to = assigned_to
        self._history(
            group,
            actor_id,
            "assigned",
            None,
            None,
            {
                "previous_assigned_to": str(previous) if previous else None,
                "assigned_to": str(assigned_to) if assigned_to else None,
            },
        )

    def feedback(self, group: AlertGroup, actor_id: uuid.UUID, feedback: str) -> None:
        self._validate_group(group)
        group.analyst_feedback = feedback
        self._history(group, actor_id, "feedback_added", None, None, {"feedback": feedback})

    def _validate_group(self, group: AlertGroup) -> None:
        if group.organization_id != self.organization_id:
            raise ValueError("Alert group organization does not match lifecycle tenant")

    def _history(
        self,
        group: AlertGroup,
        actor_id: uuid.UUID,
        action: str,
        previous_status: str | None,
        new_status: str | None,
        details: dict[str, str | None],
    ) -> None:
        self.session.add(
            AlertGroupHistory(
                organization_id=self.organization_id,
                alert_group_id=group.id,
                actor_id=actor_id,
                action=action,
                previous_status=previous_status,
                new_status=new_status,
                details=details,
            )
        )
