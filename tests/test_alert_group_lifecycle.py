from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.models import AlertGroup
from tests.conftest import OTHER_ORG_ID, TEST_ORG_ID, TEST_USER_ID


def _group(session: Session, organization_id=TEST_ORG_ID) -> AlertGroup:
    group = AlertGroup(
        organization_id=organization_id,
        correlation_key="user:alex",
        first_seen=datetime(2026, 9, 1, 16, tzinfo=UTC),
        last_seen=datetime(2026, 9, 1, 16, tzinfo=UTC),
        severity=8,
        affected_endpoint_ids=[],
        affected_users=["alex"],
        source_ips=[],
        destination_ips=[],
        mitre_attack=[],
        evidence_summary={"timeline": []},
    )
    session.add(group)
    session.commit()
    return group


def test_alert_group_lifecycle_assignment_feedback_and_audit_trail(
    client, session: Session
) -> None:
    group = _group(session)
    assignment = client.patch(
        f"/api/v1/alert-groups/{group.id}/assignment", json={"assigned_to": str(TEST_USER_ID)}
    )
    assert assignment.status_code == 200
    assert assignment.json()["assigned_to"] == str(TEST_USER_ID)
    feedback = client.post(
        f"/api/v1/alert-groups/{group.id}/feedback",
        json={"analyst_feedback": "Credential use verified"},
    )
    assert feedback.status_code == 200
    investigating = client.patch(
        f"/api/v1/alert-groups/{group.id}/status", json={"status": "investigating"}
    )
    assert investigating.status_code == 200
    resolved = client.patch(
        f"/api/v1/alert-groups/{group.id}/status",
        json={"status": "resolved", "resolution_reason": "Confirmed remediation"},
    )
    body = resolved.json()
    assert body["status"] == "resolved"
    assert body["assigned_to"] == str(TEST_USER_ID)
    assert body["analyst_feedback"] == "Credential use verified"
    assert body["resolution_reason"] == "Confirmed remediation"
    assert body["closed_at"] is not None
    history = client.get(f"/api/v1/alert-groups/{group.id}/history").json()
    assert [item["action"] for item in history] == [
        "assigned",
        "feedback_added",
        "status_changed",
        "status_changed",
    ]
    assert history[-1]["previous_status"] == "investigating"
    assert history[-1]["new_status"] == "resolved"


def test_invalid_and_terminal_transitions_are_rejected(client, session: Session) -> None:
    group = _group(session)
    assert (
        client.patch(f"/api/v1/alert-groups/{group.id}/status", json={"status": "open"}).status_code
        == 422
    )
    assert (
        client.patch(
            f"/api/v1/alert-groups/{group.id}/status", json={"status": "resolved"}
        ).status_code
        == 422
    )
    assert (
        client.patch(
            f"/api/v1/alert-groups/{group.id}/status",
            json={"status": "false_positive", "resolution_reason": "Known benign tool"},
        ).status_code
        == 200
    )
    assert (
        client.patch(
            f"/api/v1/alert-groups/{group.id}/status", json={"status": "investigating"}
        ).status_code
        == 422
    )


def test_alert_group_lifecycle_is_tenant_scoped_and_idor_safe(client, session: Session) -> None:
    foreign = _group(session, OTHER_ORG_ID)
    assert (
        client.patch(
            f"/api/v1/alert-groups/{foreign.id}/status", json={"status": "investigating"}
        ).status_code
        == 404
    )
    assert (
        client.patch(
            f"/api/v1/alert-groups/{foreign.id}/assignment", json={"assigned_to": str(TEST_USER_ID)}
        ).status_code
        == 404
    )
    assert client.get(f"/api/v1/alert-groups/{foreign.id}/history").status_code == 404
