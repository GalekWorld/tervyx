from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.models import AlertGroup, Endpoint, Incident
from app.services.incident_lifecycle import IncidentLifecycleService
from app.services.incidents import IncidentEngine
from tests.conftest import OTHER_ORG_ID, TEST_ORG_ID, TEST_USER_ID


def _incident(session: Session, organization_id=TEST_ORG_ID) -> Incident:
    incident = Incident(
        organization_id=organization_id,
        title="Lifecycle incident",
        severity=8,
        priority="high",
        status="open",
        confidence=0.8,
        occurred_at=datetime(2026, 9, 1, 16, tzinfo=UTC),
        first_seen=datetime(2026, 9, 1, 16, tzinfo=UTC),
        last_seen=datetime(2026, 9, 1, 16, tzinfo=UTC),
        affected_endpoint_ids=[],
        affected_users=["alex"],
        source_ips=[],
        destination_ips=[],
        mitre_attack=[],
        evidence={},
        timeline=[],
        sla_due_at=datetime(2026, 9, 2, 16, tzinfo=UTC),
    )
    session.add(incident)
    session.commit()
    return incident


def test_incident_full_lifecycle_assignment_sla_and_history(client, session: Session) -> None:
    incident = _incident(session)
    assignment = client.patch(
        f"/api/v1/incidents/{incident.id}/assignment", json={"assigned_to": str(TEST_USER_ID)}
    )
    assert assignment.status_code == 200
    assert assignment.json()["sla_due_at"].startswith("2026-09-02T16:00:00")
    for status in ("investigating", "contained"):
        assert (
            client.patch(
                f"/api/v1/incidents/{incident.id}/status", json={"status": status}
            ).status_code
            == 200
        )
    resolved = client.post(
        f"/api/v1/incidents/{incident.id}/resolve",
        json={"status": "resolved", "resolution": "Threat removed"},
    )
    assert resolved.status_code == 200
    assert resolved.json()["closed_at"] is not None
    assert resolved.json()["assigned_to"] == str(TEST_USER_ID)
    reopened = client.post(
        f"/api/v1/incidents/{incident.id}/reopen", json={"reason": "New evidence"}
    )
    assert reopened.status_code == 200
    assert reopened.json()["status"] == "reopened"
    assert reopened.json()["closed_at"] is None
    final = client.post(
        f"/api/v1/incidents/{incident.id}/resolve",
        json={"status": "resolved", "resolution": "Second remediation"},
    )
    assert final.status_code == 200
    history = client.get(f"/api/v1/incidents/{incident.id}/history").json()
    assert [item["action"] for item in history] == [
        "assigned",
        "status_changed",
        "status_changed",
        "status_changed",
        "status_changed",
        "reopened",
        "status_changed",
    ]
    assert history[-1]["new_status"] == "resolved"


def test_invalid_closure_and_false_positive_rules(client, session: Session) -> None:
    incident = _incident(session)
    assert (
        client.patch(f"/api/v1/incidents/{incident.id}/status", json={"status": "open"}).status_code
        == 422
    )
    assert (
        client.post(
            f"/api/v1/incidents/{incident.id}/resolve",
            json={"status": "resolved", "resolution": ""},
        ).status_code
        == 422
    )
    assert (
        client.post(
            f"/api/v1/incidents/{incident.id}/resolve",
            json={"status": "false_positive", "resolution": "Approved activity"},
        ).status_code
        == 200
    )
    assert (
        client.patch(
            f"/api/v1/incidents/{incident.id}/status", json={"status": "investigating"}
        ).status_code
        == 422
    )


def _group(session: Session, endpoint: Endpoint, when: datetime) -> AlertGroup:
    group = AlertGroup(
        organization_id=endpoint.organization_id,
        correlation_key="user:alex",
        first_seen=when,
        last_seen=when,
        severity=8,
        affected_endpoint_ids=[str(endpoint.id)],
        affected_users=["alex"],
        source_ips=[],
        destination_ips=[],
        mitre_attack=[],
        evidence_summary={"timeline": []},
    )
    session.add(group)
    session.flush()
    return group


def test_new_alert_group_does_not_silently_update_closed_incident(
    session: Session, endpoint: Endpoint
) -> None:
    engine = IncidentEngine(session, TEST_ORG_ID, window_seconds=3600)
    first = engine.correlate(_group(session, endpoint, datetime(2026, 9, 1, 17, tzinfo=UTC)))
    IncidentLifecycleService(session, TEST_ORG_ID).transition(
        first, TEST_USER_ID, "resolved", "Completed response"
    )
    session.flush()
    second = engine.correlate(
        _group(session, endpoint, datetime(2026, 9, 1, 17, tzinfo=UTC) + timedelta(minutes=1))
    )
    assert second.id != first.id
    assert first.status == "resolved"
    assert len(first.alert_groups) == 1


def test_incident_lifecycle_idor_is_tenant_scoped(client, session: Session) -> None:
    foreign = _incident(session, OTHER_ORG_ID)
    assert (
        client.post(
            f"/api/v1/incidents/{foreign.id}/reopen", json={"reason": "No access"}
        ).status_code
        == 404
    )
    assert (
        client.patch(
            f"/api/v1/incidents/{foreign.id}/assignment", json={"assigned_to": str(TEST_USER_ID)}
        ).status_code
        == 404
    )
    assert client.get(f"/api/v1/incidents/{foreign.id}/history").status_code == 404
