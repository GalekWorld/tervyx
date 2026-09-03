"""Deterministic, tenant-scoped correlation of detection alerts into alert groups."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session, selectinload

from app.core.config import get_settings
from app.models import Alert, AlertGroup
from app.services.incidents import IncidentEngine

DEFAULT_CORRELATION_WINDOW_SECONDS = 3600


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _unique(existing: list[str], additions: list[str]) -> list[str]:
    return list(dict.fromkeys([*existing, *additions]))


class AlertCorrelationService:
    def __init__(
        self, session: Session, organization_id, window_seconds: int | None = None
    ) -> None:
        self.session = session
        self.organization_id = organization_id
        if window_seconds is None:
            window_seconds = get_settings().alert_correlation_window_seconds
        self.window = timedelta(seconds=window_seconds)

    def correlate(self, alert: Alert) -> AlertGroup:
        """Assign an alert once, updating an open compatible group when available."""
        if alert.organization_id != self.organization_id:
            raise ValueError("Alert organization does not match correlation tenant")
        self.session.flush()
        current = self._context(alert)
        self._lock(current, alert)
        group = self._compatible_group(alert, current)
        if group is None:
            group = AlertGroup(
                organization_id=self.organization_id,
                correlation_key=self._group_key(alert, current),
                first_seen=alert.occurred_at,
                last_seen=alert.occurred_at,
                severity=self._effective_severity(
                    alert.severity, int(current.get("criticality", 3))
                ),
                affected_endpoint_ids=current["endpoints"],
                affected_users=current["users"],
                source_ips=current["source_ips"],
                destination_ips=current["destination_ips"],
                mitre_attack=alert.mitre_attack,
                evidence_summary=self._summary([], alert),
            )
            self.session.add(group)
        if alert not in group.alerts:
            group.alerts.append(alert)
            self._update(group, alert, current)
        IncidentEngine(self.session, self.organization_id).correlate(group)
        return group

    def _lock(self, current: dict[str, Any], alert: Alert) -> None:
        """Serialize creation for the same tenant/entity on PostgreSQL.

        Row locks protect existing groups; this transaction advisory lock also
        closes the race where two first compatible alerts arrive simultaneously.
        """
        if self.session.bind is None or self.session.bind.dialect.name != "postgresql":
            return
        entity = current["users"] or current["source_ips"] or current["endpoints"]
        key = f"{self.organization_id}:{entity[0] if entity else alert.id}"
        self.session.execute(text("SELECT pg_advisory_xact_lock(hashtext(:key))"), {"key": key})

    def _compatible_group(self, alert: Alert, current: dict[str, Any]) -> AlertGroup | None:
        earliest = _as_utc(alert.occurred_at) - self.window
        groups = list(
            self.session.scalars(
                select(AlertGroup)
                .options(selectinload(AlertGroup.alerts))
                .where(
                    AlertGroup.organization_id == self.organization_id,
                    AlertGroup.last_seen >= earliest,
                    AlertGroup.status.in_(("open", "investigating")),
                )
                .order_by(AlertGroup.last_seen.desc())
                .with_for_update()
            )
        )
        ranked: list[tuple[int, AlertGroup]] = []
        for group in groups:
            score, reasons = self._score(group, alert, current)
            if score >= 45:
                ranked.append((score, group))
                group.evidence_summary = {
                    **group.evidence_summary,
                    "last_correlation": {"score": score, "reasons": reasons},
                }
        if ranked:
            ranked.sort(key=lambda item: (-item[0], -_as_utc(item[1].last_seen).timestamp()))
            return ranked[0][1]
        return None

    @staticmethod
    def _compatible(group: AlertGroup, alert: Alert, current: dict[str, Any]) -> bool:
        return AlertCorrelationService._score(group, alert, current)[0] >= 45

    @staticmethod
    def _score(group: AlertGroup, alert: Alert, current: dict[str, Any]) -> tuple[int, list[str]]:
        score = 100 if group.correlation_key == alert.correlation_key else 0
        reasons = ["same_correlation_key"] if score else []
        endpoint_overlap = bool(set(group.affected_endpoint_ids) & set(current["endpoints"]))
        user_overlap = bool(set(group.affected_users) & set(current["users"]))
        ip_overlap = bool(
            (set(group.source_ips) | set(group.destination_ips))
            & (set(current["source_ips"]) | set(current["destination_ips"]))
        )
        group_mitre = {item["id"] for item in group.mitre_attack}
        alert_mitre = {item["id"] for item in alert.mitre_attack}
        if endpoint_overlap:
            score += 30
            reasons.append("shared_asset")
        if user_overlap:
            score += 25
            reasons.append("shared_user")
        if ip_overlap:
            score += 20
            reasons.append("shared_ip")
        if group_mitre & alert_mitre:
            score += 15
            reasons.append("shared_mitre")
        return score, reasons

    @staticmethod
    def _context(alert: Alert) -> dict[str, Any]:
        context: dict[str, Any] = alert.evidence.get("correlation_context", {})
        criticality = int(alert.evidence.get("asset_criticality", 3) or 3)
        return {
            "endpoints": [str(alert.endpoint_id)],
            "users": [str(value) for value in context.get("users", []) if value],
            "source_ips": [str(value) for value in context.get("source_ips", []) if value],
            "destination_ips": [
                str(value) for value in context.get("destination_ips", []) if value
            ],
            "criticality": criticality,
        }

    @staticmethod
    def _effective_severity(severity: int, criticality: int) -> int:
        return min(10, max(0, severity + max(0, criticality - 3)))

    @staticmethod
    def _group_key(alert: Alert, current: dict[str, Any]) -> str:
        if current["users"]:
            return f"user:{current['users'][0]}"
        if current["source_ips"]:
            return f"source_ip:{current['source_ips'][0]}"
        return alert.correlation_key or f"endpoint:{alert.endpoint_id}"

    def _update(self, group: AlertGroup, alert: Alert, current: dict[str, Any]) -> None:
        group.first_seen = min(_as_utc(group.first_seen), _as_utc(alert.occurred_at))
        group.last_seen = max(_as_utc(group.last_seen), _as_utc(alert.occurred_at))
        group.severity = max(
            group.severity,
            self._effective_severity(alert.severity, int(current.get("criticality", 3))),
        )
        group.affected_endpoint_ids = _unique(group.affected_endpoint_ids, current["endpoints"])
        group.affected_users = _unique(group.affected_users, current["users"])
        group.source_ips = _unique(group.source_ips, current["source_ips"])
        group.destination_ips = _unique(group.destination_ips, current["destination_ips"])
        technique_by_id = {item["id"]: item for item in group.mitre_attack}
        technique_by_id.update({item["id"]: item for item in alert.mitre_attack})
        group.mitre_attack = list(technique_by_id.values())
        group.evidence_summary = self._summary(group.alerts, alert)

    @staticmethod
    def _summary(alerts: list[Alert], latest: Alert) -> dict[str, object]:
        timeline = [
            {
                "alert_id": str(item.id),
                "occurred_at": item.occurred_at.isoformat(),
                "rule_id": item.rule_id,
                "severity": item.severity,
                "title": item.title,
            }
            for item in sorted(alerts, key=lambda item: _as_utc(item.occurred_at))
        ]
        return {
            "alert_count": len(alerts),
            "latest_alert_id": str(latest.id),
            "timeline": timeline,
            "asset_criticality": int(latest.evidence.get("asset_criticality", 3) or 3),
        }
