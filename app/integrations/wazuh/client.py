import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class WazuhClientError(RuntimeError):
    pass


class WazuhAuthenticationError(WazuhClientError):
    pass


class WazuhRateLimitError(WazuhClientError):
    pass


class WazuhResponseError(WazuhClientError):
    pass


@dataclass(frozen=True)
class WazuhPage:
    items: list[dict[str, Any]]
    cursor: list[Any] | None = None


class WazuhClient:
    def __init__(
        self,
        base_url: str,
        credentials: dict[str, Any],
        *,
        timeout: float = 15.0,
        max_retries: int = 3,
        client: httpx.Client | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.credentials = credentials
        self.max_retries = max_retries
        self.sleep = sleep
        verify: bool | str = bool(credentials.get("verify_ssl", True))
        if credentials.get("ca_bundle"):
            verify = str(credentials["ca_bundle"])
        self._client = client or httpx.Client(timeout=httpx.Timeout(timeout), verify=verify)
        self._token: str | None = None

    def authenticate(self) -> str:
        username = self.credentials.get("username")
        password = self.credentials.get("password")
        if not username or not password:
            raise WazuhAuthenticationError("Wazuh manager credentials are incomplete")
        response = self._request(
            "POST",
            f"{self.base_url}/security/user/authenticate",
            auth=httpx.BasicAuth(str(username), str(password)),
        )
        try:
            body = response.json()
            token = body["data"]["token"]
        except (ValueError, KeyError, TypeError) as exc:
            raise WazuhResponseError("Malformed Wazuh authentication response") from exc
        if not isinstance(token, str) or not token:
            raise WazuhResponseError("Wazuh authentication token is missing")
        self._token = token
        return token

    def test_connection(self) -> dict[str, Any]:
        return self.health()

    def health(self) -> dict[str, Any]:
        return self._manager_get("/")

    def fetch_agents(self, *, offset: int = 0, limit: int = 500) -> list[dict[str, Any]]:
        body = self._manager_get("/agents", params={"offset": offset, "limit": limit})
        return self._affected_items(body, "agents")

    def fetch_agent(self, agent_id: str) -> dict[str, Any]:
        body = self._manager_get("/agents", params={"agents_list": agent_id, "limit": 1})
        items = self._affected_items(body, "agent")
        if not items:
            raise WazuhResponseError("Wazuh agent response is empty")
        return items[0]

    def fetch_alerts(
        self,
        *,
        since: datetime | None = None,
        cursor: list[Any] | None = None,
        limit: int = 500,
    ) -> WazuhPage:
        indexer_url = str(self.credentials.get("indexer_url") or self.base_url).rstrip("/")
        query: dict[str, Any] = {"match_all": {}}
        if since is not None:
            query = {"range": {"timestamp": {"gt": since.isoformat()}}}
        request_body: dict[str, Any] = {
            "size": limit,
            "query": query,
            "sort": [{"timestamp": "asc"}, {"_id": "asc"}],
        }
        if cursor:
            request_body["search_after"] = cursor
        auth = self._indexer_auth()
        headers = None
        if self.credentials.get("indexer_token"):
            headers = {"Authorization": f"Bearer {self.credentials['indexer_token']}"}
        response = self._request(
            "POST",
            f"{indexer_url}/wazuh-alerts*/_search",
            json=request_body,
            auth=auth,
            headers=headers,
        )
        try:
            hits = response.json()["hits"]["hits"]
            if not isinstance(hits, list):
                raise TypeError
            items = []
            for hit in hits:
                payload = dict(hit["_source"])
                payload.setdefault("id", str(hit["_id"]))
                items.append(payload)
            next_cursor = hits[-1].get("sort") if hits else None
        except (ValueError, KeyError, TypeError) as exc:
            raise WazuhResponseError("Malformed Wazuh indexer response") from exc
        return WazuhPage(items=items, cursor=next_cursor)

    def _manager_get(self, path: str, **kwargs: Any) -> dict[str, Any]:
        if self._token is None:
            self.authenticate()
        response = self._request(
            "GET",
            f"{self.base_url}{path}",
            headers={"Authorization": f"Bearer {self._token}"},
            **kwargs,
        )
        try:
            body = response.json()
        except ValueError as exc:
            raise WazuhResponseError("Malformed JSON from Wazuh manager") from exc
        if not isinstance(body, dict) or body.get("error", 0) not in (0, None):
            raise WazuhResponseError("Wazuh manager returned an invalid response")
        return body

    def _indexer_auth(self) -> httpx.BasicAuth | None:
        username = self.credentials.get("indexer_username")
        password = self.credentials.get("indexer_password")
        return httpx.BasicAuth(str(username), str(password)) if username and password else None

    def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        for attempt in range(self.max_retries + 1):
            try:
                response = self._client.request(method, url, **kwargs)
            except httpx.TransportError as exc:
                if attempt == self.max_retries:
                    raise WazuhClientError("Wazuh transport failure") from exc
                self.sleep(2**attempt)
                continue
            if response.status_code in (401, 403):
                raise WazuhAuthenticationError("Wazuh authentication or authorization failed")
            if response.status_code == 429:
                if attempt == self.max_retries:
                    raise WazuhRateLimitError("Wazuh rate limit exceeded")
                self.sleep(float(response.headers.get("Retry-After", 2**attempt)))
                continue
            if response.status_code >= 500:
                if attempt == self.max_retries:
                    raise WazuhClientError(f"Wazuh server error ({response.status_code})")
                self.sleep(2**attempt)
                continue
            if response.status_code >= 400:
                raise WazuhClientError(f"Wazuh request failed ({response.status_code})")
            return response
        raise WazuhClientError("Wazuh request failed")

    @staticmethod
    def _affected_items(body: dict[str, Any], resource: str) -> list[dict[str, Any]]:
        try:
            items = body["data"]["affected_items"]
        except (KeyError, TypeError) as exc:
            raise WazuhResponseError(f"Malformed Wazuh {resource} response") from exc
        if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
            raise WazuhResponseError(f"Malformed Wazuh {resource} response")
        return items
