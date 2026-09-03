import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.integrations.base import AdapterError
from app.integrations.registry import AdapterRegistry
from app.integrations.wazuh import WazuhAdapter
from app.models import Alert, SecurityEvent
from app.services.ingestion import IngestionService
from tests.conftest import OTHER_ORG_ID, TEST_ORG_ID


def _payload(identifier: str, timestamp: str, **data: str) -> dict:
    return {
        "id": identifier,
        "timestamp": timestamp,
        "agent": {"id": "detector-agent", "name": "detector-host"},
        "rule": {"level": 5, "description": "login event", "groups": ["login"]},
        "data": data,
    }


def _service(session: Session) -> IngestionService:
    return IngestionService(session, AdapterRegistry([WazuhAdapter()]))


def test_failed_login_sequence_creates_detection_alert_with_evidence_and_mitre(
    session: Session,
) -> None:
    service = _service(session)
    base = "2026-09-01T12:0"
    for number in range(5):
        service.ingest(
            TEST_ORG_ID,
            "wazuh",
            _payload(
                f"failed-{number}",
                f"{base}{number}:00Z",
                action="login",
                outcome="failure",
                user="alex",
            ),
        )

    alert = session.scalar(
        select(Alert).where(
            Alert.organization_id == TEST_ORG_ID, Alert.rule_id == "multiple_failed_logins"
        )
    )
    assert alert is not None
    assert alert.severity == 7
    assert alert.evidence["failed_login_count"] == 5
    assert alert.mitre_attack == [{"id": "T1110", "name": "Brute Force"}]
    assert len(alert.security_events) == 5
    assert all(item.organization_id == TEST_ORG_ID for item in alert.security_events)


def test_success_after_failed_logins_and_keyword_rules_match(session: Session) -> None:
    service = _service(session)
    for number in range(3):
        service.ingest(
            TEST_ORG_ID,
            "wazuh",
            _payload(
                f"prior-{number}",
                f"2026-09-01T13:0{number}:00Z",
                action="login",
                outcome="failure",
                user="alex",
            ),
        )
    service.ingest(
        TEST_ORG_ID,
        "wazuh",
        _payload(
            "success",
            "2026-09-01T13:05:00Z",
            action="login",
            outcome="success",
            user="alex",
        ),
    )
    service.ingest(
        TEST_ORG_ID,
        "wazuh",
        _payload(
            "powershell",
            "2026-09-01T13:06:00Z",
            action="process_start",
            process_name="powershell.exe",
            command_line="powershell -NoP -EncodedCommand AAA",
        ),
    )

    rules = set(
        session.scalars(
            select(Alert.rule_id).where(
                Alert.organization_id == TEST_ORG_ID, Alert.source == "detection"
            )
        )
    )
    assert {"successful_login_after_failures", "suspicious_powershell"} <= rules


@pytest.mark.parametrize(
    ("identifier", "data", "rule_id", "mitre_id"),
    [
        ("admin", {"action": "create_admin"}, "admin_account_created", "T1098"),
        ("privilege", {"action": "privilege_escalation"}, "privilege_escalation", "T1068"),
        (
            "controls",
            {"action": "security_control_disabled"},
            "security_controls_disabled",
            "T1562.001",
        ),
        (
            "temp",
            {"command_line": r"C:\Users\alex\AppData\Local\Temp\run.exe"},
            "execution_from_temp",
            "T1204.002",
        ),
    ],
)
def test_remaining_initial_rules_match(
    session: Session, identifier: str, data: dict[str, str], rule_id: str, mitre_id: str
) -> None:
    _service(session).ingest(
        TEST_ORG_ID,
        "wazuh",
        _payload(identifier, "2026-09-01T13:30:00Z", **data),
    )
    alert = session.scalar(select(Alert).where(Alert.rule_id == rule_id))
    assert alert is not None
    assert alert.mitre_attack[0]["id"] == mitre_id


def test_no_match_and_duplicate_do_not_create_extra_detection_alerts(session: Session) -> None:
    service = _service(session)
    payload = _payload(
        "benign", "2026-09-01T14:00:00Z", action="login", outcome="success", user="alex"
    )
    assert service.ingest(TEST_ORG_ID, "wazuh", payload).duplicate is False
    assert service.ingest(TEST_ORG_ID, "wazuh", payload).duplicate is True
    assert session.scalar(select(func.count()).select_from(SecurityEvent)) == 1
    assert (
        session.scalar(select(func.count()).select_from(Alert).where(Alert.source == "detection"))
        == 0
    )


def test_malformed_events_are_rejected_without_partial_persistence(session: Session) -> None:
    with pytest.raises(AdapterError):
        _service(session).ingest(
            TEST_ORG_ID,
            "wazuh",
            _payload("bad", "not-a-date", action="login", outcome="failure"),
        )
    assert session.scalar(select(func.count()).select_from(SecurityEvent)) == 0


def test_detection_is_tenant_scoped_and_not_readable_by_idor(client, session: Session) -> None:
    service = _service(session)
    for number in range(5):
        service.ingest(
            OTHER_ORG_ID,
            "wazuh",
            _payload(
                f"other-{number}",
                f"2026-09-01T15:0{number}:00Z",
                action="login",
                outcome="failure",
                user="alex",
            ),
        )
    assert (
        session.scalar(
            select(func.count())
            .select_from(Alert)
            .where(Alert.organization_id == TEST_ORG_ID, Alert.source == "detection")
        )
        == 0
    )
    foreign_alert = session.scalar(
        select(Alert).where(
            Alert.organization_id == OTHER_ORG_ID,
            Alert.rule_id == "multiple_failed_logins",
        )
    )
    assert foreign_alert is not None
    assert client.get(f"/api/v1/alerts/{foreign_alert.id}").status_code == 404
