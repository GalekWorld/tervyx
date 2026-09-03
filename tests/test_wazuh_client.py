import httpx
import pytest

from app.integrations.wazuh.client import (
    WazuhAuthenticationError,
    WazuhClient,
    WazuhClientError,
    WazuhRateLimitError,
    WazuhResponseError,
)


def test_production_wazuh_requires_verified_tls(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.integrations.wazuh.client.get_settings",
        lambda: type("S", (), {"app_env": "production"})(),
    )
    with pytest.raises(WazuhClientError, match="TLS verification"):
        WazuhClient("http://wazuh.internal", {"verify_ssl": True})


def make_client(handler, *, retries=2, sleeps=None):
    transport = httpx.MockTransport(handler)
    return WazuhClient(
        "https://manager:55000",
        {"username": "user", "password": "top-secret", "indexer_url": "https://indexer:9200"},
        max_retries=retries,
        client=httpx.Client(transport=transport),
        sleep=(sleeps.append if sleeps is not None else lambda _: None),
    )


def test_authenticate_and_fetch_agents() -> None:
    def handler(request):
        if request.url.path.endswith("authenticate"):
            return httpx.Response(200, json={"data": {"token": "jwt-secret"}})
        assert request.headers["Authorization"] == "Bearer jwt-secret"
        return httpx.Response(200, json={"error": 0, "data": {"affected_items": [{"id": "001"}]}})

    assert make_client(handler).fetch_agents() == [{"id": "001"}]


def test_fetch_agent_uses_wazuh_414_query_contract() -> None:
    def handler(request):
        if request.url.path.endswith("authenticate"):
            return httpx.Response(200, json={"data": {"token": "jwt-secret"}})
        assert request.url.path == "/agents"
        assert request.url.params["agents_list"] == "001"
        assert request.url.params["limit"] == "1"
        return httpx.Response(200, json={"error": 0, "data": {"affected_items": [{"id": "001"}]}})

    assert make_client(handler).fetch_agent("001") == {"id": "001"}


@pytest.mark.parametrize("status", [401, 403])
def test_authentication_failures_are_not_retried(status: int) -> None:
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(status)

    with pytest.raises(WazuhAuthenticationError):
        make_client(handler).authenticate()
    assert len(calls) == 1


def test_rate_limit_retries_then_fails() -> None:
    sleeps = []
    with pytest.raises(WazuhRateLimitError):
        make_client(
            lambda request: httpx.Response(429, headers={"Retry-After": "0.25"}),
            retries=2,
            sleeps=sleeps,
        ).authenticate()
    assert len(sleeps) == 2
    assert all(0.1875 <= delay <= 0.3125 for delay in sleeps)


def test_server_error_retries_with_exponential_backoff() -> None:
    calls, sleeps = [], []

    def handler(request):
        calls.append(request)
        if len(calls) < 3:
            return httpx.Response(503)
        return httpx.Response(200, json={"data": {"token": "ok"}})

    assert make_client(handler, sleeps=sleeps).authenticate() == "ok"
    assert len(sleeps) == 2
    assert 0.75 <= sleeps[0] <= 1.25
    assert 1.5 <= sleeps[1] <= 2.5


def test_malformed_indexer_response() -> None:
    client = make_client(lambda request: httpx.Response(200, json={"unexpected": True}))
    with pytest.raises(WazuhResponseError, match="indexer"):
        client.fetch_alerts()


def test_fetch_alerts_extracts_search_cursor(wazuh_payload: dict) -> None:
    client = make_client(
        lambda request: httpx.Response(
            200,
            json={
                "hits": {
                    "hits": [
                        {
                            "_id": "index-id",
                            "_source": wazuh_payload,
                            "sort": ["2026-08-31", "index-id"],
                        }
                    ]
                }
            },
        )
    )
    page = client.fetch_alerts()
    assert page.items[0]["id"] == wazuh_payload["id"]
    assert page.cursor == ["2026-08-31", "index-id"]
