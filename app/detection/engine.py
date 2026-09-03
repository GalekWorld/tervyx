from __future__ import annotations

import hashlib

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.detection.rules import DEFAULT_RULES, DetectionRule, RuleMatch
from app.models import Alert, Endpoint, SecurityEvent
from app.services.correlation import AlertCorrelationService
from app.services.detection import DetectionConfigurationService


class DetectionEngine:
    """Evaluates an ordered immutable rule set and persists one alert per match."""

    def __init__(self, rules: tuple[DetectionRule, ...] = DEFAULT_RULES) -> None:
        self.rules = rules

    def evaluate(self, session: Session, event: SecurityEvent) -> list[Alert]:
        alerts: list[Alert] = []
        configuration_service = DetectionConfigurationService(session, event.organization_id)
        for rule in self.rules:
            configuration = configuration_service.active(rule.rule_id)
            if not configuration.enabled:
                continue
            metric = configuration_service.metric(rule.rule_id)
            metric.executions += 1
            match = rule.evaluate(session, event)
            if match is not None:
                metric.matches += 1
                metric.last_match = event.occurred_at
                correlation_key = self._correlation_key(event, match)
                if configuration_service.suppresses(
                    rule.rule_id,
                    correlation_key,
                    event.occurred_at,
                    configuration.suppression_window_seconds,
                ):
                    metric.alerts_suppressed += 1
                    continue
                alert = self._alert(session, event, match, correlation_key, configuration.version)
                session.add(alert)
                AlertCorrelationService(session, event.organization_id).correlate(alert)
                alerts.append(alert)
                metric.alerts_created += 1
        return alerts

    @staticmethod
    def _alert(
        session: Session,
        event: SecurityEvent,
        match: RuleMatch,
        correlation_key: str,
        rule_version: int,
    ) -> Alert:
        digest = hashlib.sha256(
            f"{match.rule_id}:{','.join(str(item) for item in match.related_event_ids)}".encode()
        ).hexdigest()[:32]
        alert = Alert(
            organization_id=event.organization_id,
            endpoint_id=event.endpoint_id,
            source="detection",
            external_id=f"{match.rule_id}:{digest}",
            title=match.title,
            description=match.description,
            severity=match.severity,
            status="open",
            occurred_at=event.occurred_at,
            rule_id=match.rule_id,
            mitre_attack=[{"id": item[0], "name": item[1]} for item in match.mitre_attack],
            evidence={
                **match.evidence,
                "detection_trace": {
                    "rule_id": match.rule_id,
                    "rule_version": rule_version,
                    "reason": match.description,
                    "matched_evidence": match.evidence,
                    "related_event_ids": [str(item) for item in match.related_event_ids],
                },
                "correlation_key": correlation_key,
                "correlation_context": {
                    "users": [
                        value
                        for value in (
                            event.normalized_data.get("actor"),
                            event.normalized_data.get("target"),
                            match.evidence.get("subject"),
                        )
                        if value
                    ],
                    "source_ips": (
                        [event.normalized_data.get("source_ip")]
                        if event.normalized_data.get("source_ip")
                        else []
                    ),
                    "destination_ips": (
                        [event.normalized_data.get("destination_ip")]
                        if event.normalized_data.get("destination_ip")
                        else []
                    ),
                },
            },
            rule_version=rule_version,
            correlation_key=correlation_key,
        )
        endpoint = session.get(Endpoint, event.endpoint_id)
        criticality = endpoint.criticality if endpoint is not None else 3
        alert.evidence["asset_criticality"] = criticality
        alert.evidence["prioritization"] = {
            "base_severity": match.severity,
            "asset_criticality": criticality,
            "effective_severity": min(10, match.severity + max(0, criticality - 3)),
            "formula": "min(10, base_severity + max(0, criticality - 3))",
        }
        related_events = list(
            session.scalars(
                select(SecurityEvent).where(
                    SecurityEvent.id.in_(match.related_event_ids),
                    SecurityEvent.organization_id == event.organization_id,
                )
            )
        )
        alert.security_events.extend(related_events)
        return alert

    @staticmethod
    def _correlation_key(event: SecurityEvent, match: RuleMatch) -> str:
        entity = match.evidence.get("subject") or event.normalized_data.get("actor")
        entity = entity or event.normalized_data.get("target") or f"endpoint:{event.endpoint_id}"
        return f"{match.rule_id}:{str(entity)[:400]}"
