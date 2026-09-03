from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.integrations.registry import AdapterRegistry
from app.integrations.wazuh import WazuhAdapter
from app.models import Alert, DetectionRuleConfiguration, DetectionRuleMetric
from app.services.detection import DetectionConfigurationService
from app.services.ingestion import IngestionService
from tests.conftest import OTHER_ORG_ID, TEST_ORG_ID


def _payload(identifier: str, timestamp: str, endpoint: str = "rule-host") -> dict:
    return {
        "id": identifier,
        "timestamp": timestamp,
        "agent": {"id": endpoint, "name": endpoint},
        "rule": {"level": 8, "description": "process event", "groups": ["process"]},
        "data": {
            "action": "process_start",
            "process_name": "powershell.exe",
            "command_line": "powershell -NoP -EncodedCommand AAA",
        },
    }


def _service(session: Session) -> IngestionService:
    return IngestionService(session, AdapterRegistry([WazuhAdapter()]))


def _configure(session: Session, organization_id, *, enabled: bool, window: int):
    return DetectionConfigurationService(session, organization_id).configure(
        "suspicious_powershell", enabled=enabled, suppression_window_seconds=window
    )


def test_rule_configuration_is_versioned_and_disable_prevents_evaluation(session: Session) -> None:
    first = _configure(session, TEST_ORG_ID, enabled=False, window=60)
    assert first.version == 1
    _service(session).ingest(TEST_ORG_ID, "wazuh", _payload("disabled", "2026-09-01T16:00:00Z"))
    assert (
        session.scalar(
            select(func.count()).select_from(Alert).where(Alert.rule_id == "suspicious_powershell")
        )
        == 0
    )

    second = _configure(session, TEST_ORG_ID, enabled=True, window=600)
    session.commit()
    assert second.version == 2
    assert (
        session.scalar(
            select(func.count())
            .select_from(DetectionRuleConfiguration)
            .where(DetectionRuleConfiguration.rule_id == "suspicious_powershell")
        )
        == 2
    )
    _service(session).ingest(TEST_ORG_ID, "wazuh", _payload("enabled", "2026-09-01T16:01:00Z"))
    assert (
        session.scalar(
            select(func.count()).select_from(Alert).where(Alert.rule_id == "suspicious_powershell")
        )
        == 1
    )


def test_equivalent_alerts_are_suppressed_and_metrics_are_accurate(session: Session) -> None:
    _configure(session, TEST_ORG_ID, enabled=True, window=600)
    session.commit()
    service = _service(session)
    service.ingest(TEST_ORG_ID, "wazuh", _payload("one", "2026-09-01T17:00:00Z"))
    service.ingest(TEST_ORG_ID, "wazuh", _payload("two", "2026-09-01T17:01:00Z"))
    service.ingest(TEST_ORG_ID, "wazuh", _payload("three", "2026-09-01T17:11:00Z"))

    alerts = list(
        session.scalars(
            select(Alert)
            .where(Alert.organization_id == TEST_ORG_ID, Alert.rule_id == "suspicious_powershell")
            .order_by(Alert.occurred_at)
        )
    )
    metric = session.scalar(
        select(DetectionRuleMetric).where(
            DetectionRuleMetric.organization_id == TEST_ORG_ID,
            DetectionRuleMetric.rule_id == "suspicious_powershell",
        )
    )
    assert len(alerts) == 2
    assert alerts[0].correlation_key == alerts[1].correlation_key
    assert alerts[0].rule_version == 1
    assert metric is not None
    assert (metric.executions, metric.matches) == (3, 3)
    assert (metric.alerts_created, metric.alerts_suppressed) == (2, 1)
    assert metric.last_match.isoformat().startswith("2026-09-01T17:11:00")


def test_suppression_and_metrics_are_isolated_by_tenant(session: Session) -> None:
    _configure(session, TEST_ORG_ID, enabled=True, window=600)
    _configure(session, OTHER_ORG_ID, enabled=True, window=600)
    session.commit()
    service = _service(session)
    service.ingest(TEST_ORG_ID, "wazuh", _payload("first", "2026-09-01T18:00:00Z"))
    service.ingest(OTHER_ORG_ID, "wazuh", _payload("first", "2026-09-01T18:01:00Z"))

    assert (
        session.scalar(
            select(func.count())
            .select_from(Alert)
            .where(Alert.source == "detection", Alert.rule_id == "suspicious_powershell")
        )
        == 2
    )
    assert (
        session.scalar(
            select(DetectionRuleMetric.alerts_suppressed).where(
                DetectionRuleMetric.organization_id == TEST_ORG_ID,
                DetectionRuleMetric.rule_id == "suspicious_powershell",
            )
        )
        == 0
    )
    assert (
        session.scalar(
            select(DetectionRuleMetric.alerts_suppressed).where(
                DetectionRuleMetric.organization_id == OTHER_ORG_ID,
                DetectionRuleMetric.rule_id == "suspicious_powershell",
            )
        )
        == 0
    )


def test_rule_configuration_endpoint_versions_without_cross_tenant_access(
    client, session: Session
) -> None:
    response = client.put(
        "/api/v1/detection-rules/suspicious_powershell",
        json={"enabled": False, "suppression_window_seconds": 300, "configuration": {}},
    )
    assert response.status_code == 201
    assert response.json()["version"] == 1
    assert response.json()["enabled"] is False
    foreign = _configure(session, OTHER_ORG_ID, enabled=True, window=60)
    session.commit()
    assert client.get("/api/v1/detection-rules").json() == [response.json()]
    assert foreign.organization_id != TEST_ORG_ID
