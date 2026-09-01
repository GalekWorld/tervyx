import pytest

from app.integrations.base import AdapterError
from app.integrations.wazuh import WazuhAdapter


def test_wazuh_adapter_normalizes_payload(wazuh_payload: dict) -> None:
    record = WazuhAdapter().normalize(wazuh_payload)

    assert record.source == "wazuh"
    assert record.endpoint.agent_id == "wazuh-agent-007"
    assert record.endpoint.operating_system == "Windows 11"
    assert record.event.event_type == "authentication_failed"
    assert record.event.severity == 8
    assert record.alert is not None
    assert record.alert.title == "Multiple authentication failures"


def test_wazuh_adapter_rejects_malformed_payload() -> None:
    with pytest.raises(AdapterError, match="Malformed Wazuh payload"):
        WazuhAdapter().normalize({"id": "incomplete"})
