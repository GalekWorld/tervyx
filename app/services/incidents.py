"""Deterministic, tenant-scoped incident creation from correlated alert groups."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, text
from sqlalchemy.orm import Session, selectinload

from app.core.config import get_settings
from app.models import AlertGroup, Incident
from app.services.enrichment import IncidentEnrichmentService


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _merge(existing: list[str], additions: list[str]) -> list[str]:
    return list(dict.fromkeys([*existing, *additions]))


def _priority(severity: int) -> str:
    if severity >= 9:
        return "critical"
    if severity >= 7:
        return "high"
    if severity >= 4:
        return "medium"
    return "low"


def _sla_hours(priority: str) -> float:
    base = get_settings().incident_sla_hours
    multiplier = {"critical": 1 / 6, "high": 1 / 3, "medium": 1.0, "low": 3.0}[priority]
    return max(1.0, base * multiplier)


class IncidentEngine:
    def __init__(
        self, session: Session, organization_id: uuid.UUID, window_seconds: int | None = None
    ) -> None:
        self.session = session
        self.organization_id = organization_id
        if window_seconds is None:
            window_seconds = get_settings().alert_correlation_window_seconds
        self.window = timedelta(seconds=window_seconds)

    def correlate(self, group: AlertGroup) -> Incident:
        if group.organization_id != self.organization_id:
            raise ValueError("Alert group organization does not match incident tenant")
        self.session.flush()
        self._lock(group)
        incident = self._compatible_incident(group)
        criticality = int(group.evidence_summary.get("asset_criticality", 3) or 3)
        effective_severity = min(10, group.severity + max(0, criticality - 3))
        if incident is None:
            incident = Incident(
                organization_id=self.organization_id,
                title=f"Correlated security activity: {group.correlation_key}",
                severity=effective_severity,
                priority=_priority(effective_severity),
                status="open",
                confidence=0.8,
                occurred_at=group.first_seen,
                first_seen=group.first_seen,
                last_seen=group.last_seen,
                correlation_key=group.correlation_key,
                affected_endpoint_ids=group.affected_endpoint_ids,
                affected_users=group.affected_users,
                source_ips=group.source_ips,
                destination_ips=group.destination_ips,
                mitre_attack=group.mitre_attack,
                evidence={},
                timeline=[],
                sla_due_at=group.first_seen
                + timedelta(hours=_sla_hours(_priority(effective_severity))),
            )
            self.session.add(incident)
        if group not in incident.alert_groups:
            incident.alert_groups.append(group)
        for alert in group.alerts:
            if alert not in incident.alerts:
                incident.alerts.append(alert)
        self._update(incident, group)
        return incident

    def _lock(self, group: AlertGroup) -> None:
        if self.session.bind is None or self.session.bind.dialect.name != "postgresql":
            return
        entity = group.affected_users or group.source_ips or group.affected_endpoint_ids
        self.session.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
            {
                "key": (
                    f"incident:{self.organization_id}:"
                    f"{entity[0] if entity else group.correlation_key or group.id}"
                )
            },
        )

    def _compatible_incident(self, group: AlertGroup) -> Incident | None:
        earliest = _as_utc(group.first_seen) - self.window
        incidents = list(
            self.session.scalars(
                select(Incident)
                .options(selectinload(Incident.alert_groups), selectinload(Incident.alerts))
                .where(
                    Incident.organization_id == self.organization_id,
                    Incident.last_seen >= earliest,
                    Incident.status.in_(("open", "investigating", "contained", "reopened")),
                )
                .order_by(Incident.last_seen.desc())
                .with_for_update()
            )
        )
        for incident in incidents:
            if self._compatible(incident, group):
                return incident
        return None

    @staticmethod
    def _compatible(incident: Incident, group: AlertGroup) -> bool:
        if incident.correlation_key == group.correlation_key:
            return True
        endpoint_overlap = bool(
            set(incident.affected_endpoint_ids) & set(group.affected_endpoint_ids)
        )
        user_overlap = bool(set(incident.affected_users) & set(group.affected_users))
        ip_overlap = bool(
            (set(incident.source_ips) | set(incident.destination_ips))
            & (set(group.source_ips) | set(group.destination_ips))
        )
        incident_mitre = {item["id"] for item in incident.mitre_attack}
        group_mitre = {item["id"] for item in group.mitre_attack}
        return endpoint_overlap and (
            user_overlap or ip_overlap or bool(incident_mitre & group_mitre)
        )

    def _update(self, incident: Incident, group: AlertGroup) -> None:
        incident.first_seen = min(_as_utc(incident.first_seen), _as_utc(group.first_seen))
        incident.last_seen = max(_as_utc(incident.last_seen), _as_utc(group.last_seen))
        criticality = int(group.evidence_summary.get("asset_criticality", 3) or 3)
        incident.severity = max(
            incident.severity, min(10, group.severity + max(0, criticality - 3))
        )
        incident.priority = _priority(incident.severity)
        incident.sla_due_at = incident.first_seen + timedelta(hours=_sla_hours(incident.priority))
        incident.affected_endpoint_ids = _merge(
            incident.affected_endpoint_ids, group.affected_endpoint_ids
        )
        incident.affected_users = _merge(incident.affected_users, group.affected_users)
        incident.source_ips = _merge(incident.source_ips, group.source_ips)
        incident.destination_ips = _merge(incident.destination_ips, group.destination_ips)
        mitre = {item["id"]: item for item in incident.mitre_attack}
        mitre.update({item["id"]: item for item in group.mitre_attack})
        incident.mitre_attack = list(mitre.values())
        incident.timeline = [
            item
            for item in sorted(
                (
                    {
                        "alert_group_id": str(alert_group.id),
                        "first_seen": alert_group.first_seen.isoformat(),
                        "last_seen": alert_group.last_seen.isoformat(),
                        "severity": alert_group.severity,
                        "correlation_key": alert_group.correlation_key,
                    }
                    for alert_group in incident.alert_groups
                ),
                key=lambda item: str(item["first_seen"]),
            )
        ]
        incident.evidence = {
            "alert_group_count": len(incident.alert_groups),
            "alert_count": len(incident.alerts),
            "latest_alert_group_id": str(group.id),
            "prioritization": {
                "severity": incident.severity,
                "priority": incident.priority,
                "asset_criticality": criticality,
                "sla_hours": _sla_hours(incident.priority),
                "formula": "severity=max(base, min(10, group_severity + max(0, criticality - 3)))",
            },
        }
        IncidentEnrichmentService(self.session, self.organization_id).enrich(incident)
