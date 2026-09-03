from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.integrations.registry import AdapterRegistry
from app.integrations.wazuh import WazuhAdapter
from app.models import Alert, AlertGroup, Endpoint
from app.services.correlation import AlertCorrelationService
from app.services.ingestion import IngestionService
from tests.conftest import OTHER_ORG_ID, TEST_ORG_ID


def _payload(
    identifier: str, timestamp: str, *, action: str, outcome: str = "", **data: str
) -> dict:
    return {
        "id": identifier,
        "timestamp": timestamp,
        "agent": {"id": "correlation-agent", "name": "correlation-host"},
        "rule": {"level": 9, "description": "login event", "groups": ["login"]},
        "data": {"action": action, "outcome": outcome, "user": "alex", **data},
    }


def _service(session: Session) -> IngestionService:
    return IngestionService(session, AdapterRegistry([WazuhAdapter()]))


def test_detection_sequence_creates_one_correlated_alert_group(session: Session) -> None:
    service = _service(session)
    for number in range(5):
        service.ingest(
            TEST_ORG_ID,
            "wazuh",
            _payload(
                f"failure-{number}",
                f"2026-09-01T10:0{number}:00Z",
                action="login",
                outcome="failure",
            ),
        )
    service.ingest(
        TEST_ORG_ID,
        "wazuh",
        _payload("success", "2026-09-01T10:06:00Z", action="login", outcome="success"),
    )
    service.ingest(
        TEST_ORG_ID,
        "wazuh",
        _payload(
            "powershell",
            "2026-09-01T10:07:00Z",
            action="process_start",
            process_name="powershell.exe",
            command_line="powershell -NoP -EncodedCommand AAA",
        ),
    )

    group = session.scalar(select(AlertGroup).where(AlertGroup.organization_id == TEST_ORG_ID))
    assert group is not None
    assert len(group.alerts) == 3
    assert group.severity == 8
    assert group.affected_users == ["alex"]
    assert {item["id"] for item in group.mitre_attack} == {"T1110", "T1078", "T1059.001"}
    assert group.evidence_summary["alert_count"] == 3
    assert len(group.evidence_summary["timeline"]) == 3


def _alert(
    session: Session, endpoint: Endpoint, identifier: str, occurred_at: datetime, **context
) -> Alert:
    alert = Alert(
        organization_id=endpoint.organization_id,
        endpoint_id=endpoint.id,
        source="detection",
        external_id=identifier,
        title=identifier,
        severity=context.pop("severity", 5),
        status="open",
        occurred_at=occurred_at,
        rule_id="test_rule",
        correlation_key=context.pop("correlation_key", "test_rule:entity"),
        mitre_attack=context.pop(
            "mitre_attack", [{"id": "T1003", "name": "OS Credential Dumping"}]
        ),
        evidence={"correlation_context": context},
    )
    session.add(alert)
    session.flush()
    return alert


def test_positive_negative_window_and_severity_aggregation(
    session: Session, endpoint: Endpoint
) -> None:
    first = _alert(
        session,
        endpoint,
        "first",
        datetime(2026, 9, 1, 12, tzinfo=UTC),
        users=["alex"],
        source_ips=["10.0.0.1"],
        severity=4,
    )
    service = AlertCorrelationService(session, TEST_ORG_ID, window_seconds=300)
    first_group = service.correlate(first)
    second = _alert(
        session,
        endpoint,
        "second",
        datetime(2026, 9, 1, 12, 1, tzinfo=UTC),
        users=["alex"],
        source_ips=["10.0.0.1"],
        severity=9,
    )
    assert service.correlate(second).id == first_group.id
    assert first_group.severity == 9
    assert len(first_group.alerts) == 2

    unrelated = _alert(
        session,
        endpoint,
        "unrelated",
        datetime(2026, 9, 1, 12, 2, tzinfo=UTC),
        users=["sam"],
        source_ips=["10.0.0.2"],
        mitre_attack=[{"id": "T1059", "name": "Command and Scripting Interpreter"}],
    )
    assert service.correlate(unrelated).id != first_group.id
    outside_window = _alert(
        session,
        endpoint,
        "outside",
        datetime(2026, 9, 1, 12, 7, tzinfo=UTC),
        users=["alex"],
        source_ips=["10.0.0.1"],
    )
    assert service.correlate(outside_window).id != first_group.id


def test_duplicate_alert_correlation_is_idempotent(session: Session, endpoint: Endpoint) -> None:
    alert = _alert(
        session,
        endpoint,
        "duplicate",
        datetime(2026, 9, 1, 13, tzinfo=UTC),
        users=["alex"],
    )
    service = AlertCorrelationService(session, TEST_ORG_ID)
    first = service.correlate(alert)
    assert service.correlate(alert).id == first.id
    assert len(first.alerts) == 1
    assert session.scalar(select(func.count()).select_from(AlertGroup)) == 1


def test_alert_groups_are_tenant_scoped_and_protected_from_idor(client, session: Session) -> None:
    other_endpoint = Endpoint(
        organization_id=OTHER_ORG_ID,
        agent_id="other-correlation-agent",
        hostname="other-host",
        status="active",
    )
    session.add(other_endpoint)
    session.flush()
    foreign_alert = _alert(
        session,
        other_endpoint,
        "foreign",
        datetime(2026, 9, 1, 14, tzinfo=UTC),
        users=["alex"],
    )
    foreign_group = AlertCorrelationService(session, OTHER_ORG_ID).correlate(foreign_alert)
    session.commit()
    assert client.get(f"/api/v1/alert-groups/{foreign_group.id}").status_code == 404
    assert client.get("/api/v1/alert-groups").json() == []


def test_basic_concurrent_style_assignments_reuse_existing_group(
    session: Session, endpoint: Endpoint
) -> None:
    service = AlertCorrelationService(session, TEST_ORG_ID)
    first = _alert(
        session, endpoint, "concurrent-first", datetime(2026, 9, 1, 15, tzinfo=UTC), users=["alex"]
    )
    second = _alert(
        session,
        endpoint,
        "concurrent-second",
        datetime(2026, 9, 1, 15, tzinfo=UTC) + timedelta(seconds=1),
        users=["alex"],
    )
    group_one = service.correlate(first)
    group_two = service.correlate(second)
    assert group_one.id == group_two.id
    assert len(group_one.alerts) == 2
