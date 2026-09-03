"""Deterministic incident investigations; no probabilistic or external analysis."""

from __future__ import annotations

import uuid
from typing import Any, cast

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.models import Alert, AuditLog, Incident, IncidentEnrichment, Investigation
from app.services.enrichment import IncidentEnrichmentService

VALID_TRANSITIONS = {
    "pending": {"in_progress"},
    "in_progress": {"completed"},
    "completed": {"closed"},
    "closed": {"in_progress"},
}


class InvalidInvestigationTransition(ValueError):
    pass


class InvestigationService:
    """Create one reproducible evidence snapshot per tenant incident."""

    def __init__(self, session: Session, organization_id: uuid.UUID) -> None:
        self.session = session
        self.organization_id = organization_id

    def create_from_incident(self, incident: Incident) -> Investigation:
        if incident.organization_id != self.organization_id:
            raise ValueError("Incident organization does not match investigation tenant")
        self.session.flush()
        # Locking the subject serializes two first-time requests on PostgreSQL.
        locked = self.session.scalar(
            select(Incident)
            .options(
                selectinload(Incident.alerts).selectinload(Alert.security_events),
                selectinload(Incident.alert_groups),
                selectinload(Incident.enrichments),
            )
            .where(
                Incident.id == incident.id,
                Incident.organization_id == self.organization_id,
            )
            .with_for_update()
        )
        if locked is None:
            raise ValueError("Incident not found in investigation tenant")
        incident = locked
        existing = self.session.scalar(
            select(Investigation).where(
                Investigation.organization_id == self.organization_id,
                Investigation.incident_id == incident.id,
            )
        )
        if existing is not None:
            return existing

        IncidentEnrichmentService(self.session, self.organization_id).enrich(incident)
        self.session.flush()
        enrichments = list(
            self.session.scalars(
                select(IncidentEnrichment)
                .where(
                    IncidentEnrichment.organization_id == self.organization_id,
                    IncidentEnrichment.incident_id == incident.id,
                )
                .order_by(IncidentEnrichment.enrichment_type, IncidentEnrichment.fingerprint)
            )
        )
        evidence = [
            {
                "type": item.enrichment_type,
                "origin": {
                    "enrichment_id": str(item.id),
                    "source_type": item.source_type,
                    "source": item.source,
                    "fingerprint": item.fingerprint,
                },
                "observed_at": item.last_observed_at.isoformat(),
                "data": item.data,
            }
            for item in enrichments
        ]
        timeline = self._timeline(evidence)
        category_count = len({item["type"] for item in evidence})
        event_count = 0
        ioc_count = 0
        for item in evidence:
            data = cast(dict[str, Any], item["data"])
            if item["type"] in {"events", "detections", "assets"}:
                event_count += len(data.get("items", []))
            if item["type"] == "iocs":
                for key in ("ipv4_or_ipv6", "domains", "sha256"):
                    ioc_count += len(data.get(key, []))
        risk_score = min(100, incident.severity * 10 + event_count * 2 + ioc_count * 5)
        confidence = round(min(1.0, 0.5 + category_count * 0.1), 3)
        classification = (
            "critical"
            if incident.severity >= 9
            else "high" if incident.severity >= 7 else "medium" if incident.severity >= 4 else "low"
        )
        investigation = Investigation(
            organization_id=self.organization_id,
            incident_id=incident.id,
            risk_score=risk_score,
            classification=classification,
            confidence=confidence,
            evidence=evidence,
            timeline=timeline,
            explanation=(
                f"Deterministic investigation from {len(enrichments)} enrichment snapshots; "
                "no AI or external source was used."
            ),
            recommended_actions=self._actions(incident, ioc_count, event_count),
            status="completed",
        )
        self.session.add(investigation)
        self.session.flush()
        self.session.add(
            AuditLog(
                organization_id=self.organization_id,
                actor_type="system",
                actor_id="investigation-engine",
                action="investigation.created",
                resource_type="investigation",
                resource_id=str(investigation.id),
                details={
                    "incident_id": str(incident.id),
                    "enrichment_count": len(enrichments),
                    "timeline_count": len(timeline),
                    "risk_score": risk_score,
                },
            )
        )
        return investigation

    def transition(
        self, investigation: Investigation, actor_id: uuid.UUID, new_status: str
    ) -> Investigation:
        if investigation.organization_id != self.organization_id:
            raise ValueError("Investigation organization does not match lifecycle tenant")
        locked = self.session.scalar(
            select(Investigation)
            .where(
                Investigation.id == investigation.id,
                Investigation.organization_id == self.organization_id,
            )
            .with_for_update()
        )
        if locked is None:
            raise ValueError("Investigation not found in lifecycle tenant")
        if new_status not in VALID_TRANSITIONS.get(locked.status, set()):
            raise InvalidInvestigationTransition(
                f"Invalid transition: {locked.status} -> {new_status}"
            )
        previous = locked.status
        locked.status = new_status
        self.session.add(
            AuditLog(
                organization_id=self.organization_id,
                actor_type="user",
                actor_id=str(actor_id),
                action="investigation.status_changed",
                resource_type="investigation",
                resource_id=str(locked.id),
                details={"previous_status": previous, "new_status": new_status},
            )
        )
        return locked

    @staticmethod
    def _timeline(evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
        timeline: list[dict[str, Any]] = []
        for group in evidence:
            for item in group["data"].get("items", []):
                timestamp = item.get("occurred_at") or item.get("last_seen")
                if timestamp:
                    timeline.append(
                        {
                            "occurred_at": timestamp,
                            "type": group["type"],
                            "origin_id": item.get("id"),
                            "severity": item.get("severity"),
                        }
                    )
        return sorted(timeline, key=lambda item: (item["occurred_at"], item["origin_id"] or ""))

    @staticmethod
    def _actions(incident: Incident, ioc_count: int, event_count: int) -> list[dict[str, Any]]:
        actions = [{"action": "review_timeline", "requires_approval": False}]
        if incident.affected_endpoint_ids:
            actions.append({"action": "validate_affected_assets", "requires_approval": True})
        if ioc_count:
            actions.append({"action": "contain_observed_iocs", "requires_approval": True})
        if event_count:
            actions.append({"action": "preserve_event_evidence", "requires_approval": False})
        return actions
