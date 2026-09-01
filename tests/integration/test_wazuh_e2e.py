import json
import os

import pytest

from app.integrations.wazuh import WazuhAuthenticationError, WazuhClient, WazuhClientError

pytestmark = pytest.mark.integration


def test_real_wazuh_contract_when_configured() -> None:
    base_url = os.getenv("WAZUH_E2E_BASE_URL")
    raw_credentials = os.getenv("WAZUH_E2E_CREDENTIALS")
    if not base_url or not raw_credentials:
        pytest.skip("Real Wazuh endpoint/credentials are not available")
    credentials = json.loads(raw_credentials)
    client = WazuhClient(base_url, credentials, timeout=10, max_retries=1)
    assert client.health().get("error", 0) == 0
    agents = client.fetch_agents(limit=1)
    assert isinstance(agents, list)
    if agents:
        assert client.fetch_agent(str(agents[0]["id"]))["id"] == agents[0]["id"]

    first = client.fetch_alerts(limit=1)
    assert isinstance(first.items, list)
    if first.items and first.cursor:
        second = client.fetch_alerts(limit=1, cursor=first.cursor)
        assert not second.items or second.items[0]["id"] != first.items[0]["id"]

    invalid = dict(credentials)
    invalid["password"] = "deliberately-invalid"
    with pytest.raises(WazuhAuthenticationError):
        WazuhClient(base_url, invalid, timeout=10, max_retries=0).health()

    if credentials.get("verify_ssl") is False:
        strict = dict(credentials)
        strict["verify_ssl"] = True
        with pytest.raises(WazuhClientError):
            WazuhClient(base_url, strict, timeout=5, max_retries=0).health()
