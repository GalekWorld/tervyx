from datetime import UTC, datetime

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import Alert, Incident, Investigation, SecurityEvent
from tests.conftest import TEST_ORG_ID


def test_alert_event_incident_relationships(session: Session, endpoint) -> None:
    event = SecurityEvent(
        organization_id=TEST_ORG_ID,
        endpoint_id=endpoint.id,
        source="test",
        external_id="event-1",
        event_type="process_start",
        severity=5,
        occurred_at=datetime.now(UTC),
        raw_payload={"command": "example"},
    )
    alert = Alert(
        organization_id=TEST_ORG_ID,
        endpoint_id=endpoint.id,
        source="test",
        external_id="alert-1",
        title="Suspicious process",
        severity=6,
        status="open",
        occurred_at=datetime.now(UTC),
        security_events=[event],
    )
    incident = Incident(
        organization_id=TEST_ORG_ID,
        title="Potential compromise",
        severity=7,
        status="open",
        occurred_at=datetime.now(UTC),
        alerts=[alert],
    )
    session.add(incident)
    session.commit()

    assert alert.security_events == [event]
    assert incident.alerts == [alert]
    assert alert.incidents == [incident]


def test_investigation_requires_exactly_one_subject(session: Session) -> None:
    investigation = Investigation(
        organization_id=TEST_ORG_ID,
        risk_score=50,
        classification="unknown",
        confidence=0.5,
        evidence=[],
        explanation="Invalid without a subject",
        recommended_actions=[],
        status="pending",
    )
    session.add(investigation)
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()
