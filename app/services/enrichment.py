"""Deterministic, tenant-scoped incident enrichment.

Providers in this module only read SOC data already persisted for the tenant.
They never call an LLM or an external intelligence service, so their result is
reproducible and safe to replay after a worker retry.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import uuid
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from sqlalchemy import select, update
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.orm import Session

from app.models import AuditLog, Endpoint, Incident, IncidentEnrichment, User

_DOMAIN = re.compile(r"(?:https?://)?([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)")
_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")


class EnrichmentProvider(Protocol):
    source_type: str
    source: str

    def collect(
        self, session: Session, incident: Incident
    ) -> Iterable[tuple[str, dict[str, Any]]]: ...


@dataclass(frozen=True)
class EnrichmentResult:
    """The mutation outcome, useful to workers without mutable ORM state."""

    created_count: int
    refreshed_count: int
    fingerprints: tuple[str, ...]


def _valid_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
    except (TypeError, ValueError, AttributeError):
        return False
    return True


def _as_json(value: Any) -> Any:
    """Return a stable, JSON-safe copy without retaining ORM objects."""
    return json.loads(json.dumps(value, sort_keys=True, default=str))


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key in sorted(value):
            yield from _strings(value[key])
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


class InternalEnrichmentProvider:
    """Build reproducible enrichment from data belonging to the incident tenant."""

    source_type = "internal"
    source = "tervyx"

    def collect(self, session: Session, incident: Incident) -> Iterable[tuple[str, dict[str, Any]]]:
        endpoint_ids = sorted(
            {uuid.UUID(value) for value in incident.affected_endpoint_ids if _valid_uuid(value)},
            key=str,
        )
        endpoints = (
            list(
                session.scalars(
                    select(Endpoint)
                    .where(
                        Endpoint.organization_id == incident.organization_id,
                        Endpoint.id.in_(endpoint_ids),
                    )
                    .order_by(Endpoint.id)
                )
            )
            if endpoint_ids
            else []
        )
        if endpoints:
            yield "assets", {
                "origin": {"table": "endpoints", "ids": [str(item.id) for item in endpoints]},
                "items": [
                    {
                        "id": str(endpoint.id),
                        "hostname": endpoint.hostname,
                        "operating_system": endpoint.operating_system,
                        "ip_address": endpoint.ip_address,
                        "status": endpoint.status,
                        "last_seen": endpoint.last_seen.isoformat() if endpoint.last_seen else None,
                    }
                    for endpoint in endpoints
                ],
            }

        observed_users = sorted(set(incident.affected_users))
        users = (
            list(
                session.scalars(
                    select(User)
                    .where(
                        User.organization_id == incident.organization_id,
                        User.email.in_(observed_users),
                    )
                    .order_by(User.email)
                )
            )
            if observed_users
            else []
        )
        if observed_users:
            yield "users", {
                "origin": {"table": "incidents", "field": "affected_users"},
                "observed": observed_users,
                "known": [
                    {"id": str(user.id), "email": user.email, "display_name": user.display_name}
                    for user in users
                ],
            }

        alerts = sorted(
            (
                alert
                for alert in incident.alerts
                if alert.organization_id == incident.organization_id
            ),
            key=lambda item: str(item.id),
        )
        by_event_id = {
            event.id: event
            for alert in alerts
            for event in alert.security_events
            if event.organization_id == incident.organization_id
        }
        events = [by_event_id[event_id] for event_id in sorted(by_event_id, key=str)]
        if events:
            yield "events", {
                "origin": {"table": "security_events", "ids": [str(event.id) for event in events]},
                "items": [
                    {
                        "id": str(event.id),
                        "source": event.source,
                        "external_id": event.external_id,
                        "event_type": event.event_type,
                        "severity": event.severity,
                        "occurred_at": event.occurred_at.isoformat(),
                        "evidence": _as_json(event.normalized_data),
                    }
                    for event in events
                ],
            }
        if alerts:
            yield "detections", {
                "origin": {"table": "alerts", "ids": [str(alert.id) for alert in alerts]},
                "items": [
                    {
                        "id": str(alert.id),
                        "source": alert.source,
                        "external_id": alert.external_id,
                        "rule_id": alert.rule_id,
                        "rule_version": alert.rule_version,
                        "title": alert.title,
                        "severity": alert.severity,
                        "occurred_at": alert.occurred_at.isoformat(),
                        "mitre_attack": _as_json(alert.mitre_attack),
                        "evidence": _as_json(alert.evidence),
                    }
                    for alert in alerts
                ],
            }

        evidence_values = [
            *incident.source_ips,
            *incident.destination_ips,
            *(value for alert in alerts for value in _strings(alert.evidence)),
            *(value for event in events for value in _strings(event.normalized_data)),
        ]
        domains = sorted(
            {
                match.lower()
                for value in evidence_values
                for match in _DOMAIN.findall(value)
                if not _is_ip(match)
            }
        )
        hashes = sorted(
            {match.lower() for value in evidence_values for match in _SHA256.findall(value)}
        )
        ips = sorted(
            {value for value in evidence_values if _is_ip(value)},
            key=lambda value: (
                ipaddress.ip_address(value).version,
                ipaddress.ip_address(value).packed,
            ),
        )
        if domains or hashes or ips:
            yield "iocs", {
                "origin": {
                    "tables": ["incidents", "alerts", "security_events"],
                    "fields": ["source_ips", "destination_ips", "evidence", "normalized_data"],
                },
                "ipv4_or_ipv6": ips,
                "domains": domains,
                "sha256": hashes,
            }

        related = (
            list(
                session.scalars(
                    select(Incident)
                    .where(
                        Incident.organization_id == incident.organization_id,
                        Incident.id != incident.id,
                        Incident.correlation_key == incident.correlation_key,
                    )
                    .order_by(Incident.id)
                )
            )
            if incident.correlation_key
            else []
        )
        yield "context", {
            "origin": {"table": "incidents", "id": str(incident.id)},
            "correlation_key": incident.correlation_key,
            "status": incident.status,
            "priority": incident.priority,
            "severity": incident.severity,
            "confidence": incident.confidence,
            "first_seen": incident.first_seen.isoformat(),
            "last_seen": incident.last_seen.isoformat(),
            "mitre_attack": _as_json(incident.mitre_attack),
            "evidence": _as_json(incident.evidence),
            "alert_group_count": len(incident.alert_groups),
            "alert_count": len(alerts),
            "related_incidents": [
                {"id": str(item.id), "status": item.status, "severity": item.severity}
                for item in related
            ],
        }


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


class IncidentEnrichmentService:
    def __init__(
        self,
        session: Session,
        organization_id: uuid.UUID,
        providers: tuple[EnrichmentProvider, ...] = (InternalEnrichmentProvider(),),
    ) -> None:
        self.session, self.organization_id, self.providers = session, organization_id, providers

    def enrich(self, incident: Incident) -> EnrichmentResult:
        """Upsert an incident snapshot without issuing network calls.

        The unique fingerprint is the replay key. Native conflict handling makes
        simultaneous workers and retried transactions converge on one row per
        snapshot, while preserving the original observation time.
        """
        if incident.organization_id != self.organization_id:
            raise ValueError("Incident organization does not match enrichment tenant")
        self.session.flush()
        now = datetime.now(UTC)
        candidates = [
            (provider, enrichment_type, _as_json(data))
            for provider in self.providers
            for enrichment_type, data in provider.collect(self.session, incident)
        ]
        fingerprints: list[str] = []
        created_count = 0
        for provider, enrichment_type, data in candidates:
            encoded = json.dumps(data, sort_keys=True, separators=(",", ":"))
            fingerprint = hashlib.sha256(
                f"{provider.source_type}:{provider.source}:{enrichment_type}:{encoded}".encode()
            ).hexdigest()
            fingerprints.append(fingerprint)
            if self._insert_if_absent(incident, provider, enrichment_type, data, fingerprint, now):
                created_count += 1
            self.session.execute(
                update(IncidentEnrichment)
                .where(
                    IncidentEnrichment.organization_id == self.organization_id,
                    IncidentEnrichment.incident_id == incident.id,
                    IncidentEnrichment.fingerprint == fingerprint,
                )
                .values(last_observed_at=now)
            )
        if created_count:
            self.session.add(
                AuditLog(
                    organization_id=self.organization_id,
                    actor_type="system",
                    actor_id="incident-enrichment",
                    action="incident.enrichment.created",
                    resource_type="incident",
                    resource_id=str(incident.id),
                    details={
                        "provider": "internal",
                        "created_count": created_count,
                        "fingerprints": sorted(fingerprints),
                    },
                )
            )
        return EnrichmentResult(
            created_count=created_count,
            refreshed_count=len(candidates) - created_count,
            fingerprints=tuple(sorted(fingerprints)),
        )

    def _insert_if_absent(
        self,
        incident: Incident,
        provider: EnrichmentProvider,
        enrichment_type: str,
        data: dict[str, Any],
        fingerprint: str,
        now: datetime,
    ) -> bool:
        values = {
            "organization_id": self.organization_id,
            "incident_id": incident.id,
            "enrichment_type": enrichment_type,
            "source_type": provider.source_type,
            "source": provider.source,
            "fingerprint": fingerprint,
            "data": data,
            "observed_at": now,
            "last_observed_at": now,
        }
        dialect = self.session.bind.dialect.name if self.session.bind is not None else ""
        if dialect == "postgresql":
            statement: Any = postgresql.insert(IncidentEnrichment).values(**values)
        elif dialect == "sqlite":
            statement = sqlite.insert(IncidentEnrichment).values(**values)
        else:  # Production supports PostgreSQL; this preserves useful local DB tests.
            existing = self.session.scalar(
                select(IncidentEnrichment.id).where(
                    IncidentEnrichment.organization_id == self.organization_id,
                    IncidentEnrichment.incident_id == incident.id,
                    IncidentEnrichment.fingerprint == fingerprint,
                )
            )
            if existing is not None:
                return False
            self.session.add(IncidentEnrichment(**values))
            self.session.flush()
            return True
        statement = statement.on_conflict_do_nothing(
            index_elements=("organization_id", "incident_id", "fingerprint")
        ).returning(IncidentEnrichment.id)
        return self.session.execute(statement).scalar_one_or_none() is not None
