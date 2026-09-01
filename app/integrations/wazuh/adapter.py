from datetime import UTC, datetime
from typing import Any

from app.integrations.base import (
    AdapterError,
    NormalizedAlert,
    NormalizedEndpoint,
    NormalizedEvent,
    NormalizedSecurityRecord,
    SecuritySourceAdapter,
)


def _parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise AdapterError("Wazuh payload requires a string timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AdapterError("Wazuh timestamp is not valid ISO-8601") from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


class WazuhAdapter(SecuritySourceAdapter):
    source = "wazuh"

    def normalize(self, payload: dict[str, Any]) -> NormalizedSecurityRecord:
        try:
            alert_id = str(payload["id"])
            timestamp = _parse_timestamp(payload["timestamp"])
            agent = payload["agent"]
            rule = payload["rule"]
            agent_id = str(agent["id"])
            hostname = str(agent["name"])
            title = str(rule["description"])
            wazuh_level = int(rule["level"])
        except (KeyError, TypeError, ValueError) as exc:
            raise AdapterError(f"Malformed Wazuh payload: {exc}") from exc

        severity = max(0, min(10, round(wazuh_level * 10 / 15)))
        groups = rule.get("groups") or []
        event_type = str(groups[0]) if groups else "wazuh_alert"
        description = payload.get("full_log") or payload.get("data", {}).get("message")

        endpoint = NormalizedEndpoint(
            agent_id=agent_id,
            hostname=hostname,
            operating_system=agent.get("os", {}).get("name") or agent.get("os_name"),
            ip_address=agent.get("ip"),
            status="active",
            last_seen=timestamp,
        )
        event = NormalizedEvent(
            external_id=alert_id,
            event_type=event_type,
            severity=severity,
            occurred_at=timestamp,
            raw_payload=payload,
        )
        alert = NormalizedAlert(
            external_id=alert_id,
            title=title,
            description=str(description) if description is not None else None,
            severity=severity,
            status="open",
            occurred_at=timestamp,
        )
        return NormalizedSecurityRecord(
            source=self.source, endpoint=endpoint, event=event, alert=alert
        )
