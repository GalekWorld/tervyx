from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.integrations.registry import AdapterRegistry
from app.integrations.wazuh import WazuhAdapter
from app.models import AlertGroup, Endpoint, Incident
from app.services.incidents import IncidentEngine
from app.services.ingestion import IngestionService
from tests.conftest import OTHER_ORG_ID, TEST_ORG_ID


def _payload(
    identifier: str, timestamp: str, *, action: str, outcome: str = "", **data: str
) -> dict:
    return {
        "id": identifier,
        "timestamp": timestamp,
        "agent": {"id": "incident-agent", "name": "incident-host"},
        "rule": {"level": 9, "description": "login event", "groups": ["login"]},
        "data": {"action": action, "outcome": outcome, "user": "alex", **data},
    }


def _group(
    session: Session, endpoint: Endpoint, key: str, user: str, severity: int, when: datetime
) -> AlertGroup:
    group = AlertGroup(
        organization_id=endpoint.organization_id,
        correlation_key=key,
        first_seen=when,
        last_seen=when,
        severity=severity,
        affected_endpoint_ids=[str(endpoint.id)],
        affected_users=[user],
        source_ips=[],
        destination_ips=[],
        mitre_attack=[{"id": "T1003", "name": "OS Credential Dumping"}],
        evidence_summary={"timeline": []},
    )
    session.add(group)
    session.flush()
    return group


def test_sequence_creates_one_incident_with_group_alerts_and_evidence(session: Session) -> None:
    service = IngestionService(session, AdapterRegistry([WazuhAdapter()]))
    for number in range(5):
        service.ingest(
            TEST_ORG_ID,
            "wazuh",
            _payload(
                f"fail-{number}", f"2026-09-01T10:0{number}:00Z", action="login", outcome="failure"
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
    incident = session.scalar(select(Incident).where(Incident.organization_id == TEST_ORG_ID))
    assert incident is not None
    assert len(incident.alert_groups) == 1
    assert len(incident.alerts) == 3
    assert incident.severity == 8
    assert incident.priority == "high"
    assert incident.affected_users == ["alex"]
    assert {item["id"] for item in incident.mitre_attack} == {"T1110", "T1078", "T1059.001"}
    assert incident.evidence["alert_count"] == 3
    assert len(incident.timeline) == 1


def test_incident_engine_updates_deduplicates_and_separates_contexts(
    session: Session, endpoint: Endpoint
) -> None:
    engine = IncidentEngine(session, TEST_ORG_ID, window_seconds=600)
    first = _group(session, endpoint, "user:alex", "alex", 5, datetime(2026, 9, 1, 12, tzinfo=UTC))
    incident = engine.correlate(first)
    assert engine.correlate(first).id == incident.id
    second = _group(
        session, endpoint, "user:alex", "alex", 9, datetime(2026, 9, 1, 12, 1, tzinfo=UTC)
    )
    assert engine.correlate(second).id == incident.id
    assert incident.severity == 9
    assert incident.priority == "critical"
    assert len(incident.alert_groups) == 2
    unrelated = _group(
        session, endpoint, "user:sam", "sam", 7, datetime(2026, 9, 1, 12, 2, tzinfo=UTC)
    )
    unrelated.mitre_attack = [{"id": "T1059", "name": "Command and Scripting Interpreter"}]
    assert engine.correlate(unrelated).id != incident.id
    outside = _group(
        session,
        endpoint,
        "user:alex",
        "alex",
        7,
        datetime(2026, 9, 1, 12, tzinfo=UTC) + timedelta(minutes=12),
    )
    assert engine.correlate(outside).id != incident.id
    assert session.scalar(select(func.count()).select_from(Incident)) == 3


def test_incident_tenant_isolation_idor_and_basic_concurrency_style(
    client, session: Session, endpoint: Endpoint
) -> None:
    engine = IncidentEngine(session, TEST_ORG_ID)
    group = _group(session, endpoint, "user:alex", "alex", 8, datetime(2026, 9, 1, 14, tzinfo=UTC))
    first = engine.correlate(group)
    assert engine.correlate(group).id == first.id
    other_endpoint = Endpoint(
        organization_id=OTHER_ORG_ID, agent_id="other-incident", hostname="other", status="active"
    )
    session.add(other_endpoint)
    session.flush()
    foreign_group = _group(
        session, other_endpoint, "user:alex", "alex", 8, datetime(2026, 9, 1, 14, tzinfo=UTC)
    )
    foreign = IncidentEngine(session, OTHER_ORG_ID).correlate(foreign_group)
    session.commit()
    assert client.get(f"/api/v1/incidents/{foreign.id}").status_code == 404
    assert client.get("/api/v1/incidents").json() == [
        client.get(f"/api/v1/incidents/{first.id}").json()
    ]
