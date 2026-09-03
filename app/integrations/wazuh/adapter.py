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
        data = payload.get("data")
        if data is None:
            data = {}
        if not isinstance(data, dict):
            raise AdapterError("Wazuh payload data must be an object")
        description = payload.get("full_log") or data.get("message")
        message = str(description or "")
        action = str(data.get("action") or event_type).lower()
        outcome = str(data.get("outcome") or data.get("status") or "").lower()
        if not outcome:
            if "fail" in event_type.lower() or "failed" in message.lower():
                outcome = "failure"
            elif "success" in event_type.lower() or "accepted" in message.lower():
                outcome = "success"
        command_line = data.get("command_line") or data.get("command") or payload.get("command")
        process_name = data.get("process_name") or data.get("process")
        actor = data.get("user") or data.get("username") or data.get("srcuser")
        target = data.get("target") or data.get("target_user") or data.get("account")
        source_ip = data.get("source_ip") or data.get("srcip") or data.get("src_ip")
        destination_ip = data.get("destination_ip") or data.get("dstip") or data.get("dst_ip")

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
            normalized_data={
                "category": str(data.get("category") or event_type).lower(),
                "action": action,
                "outcome": outcome,
                "actor": str(actor) if actor is not None else None,
                "target": str(target) if target is not None else None,
                "source_ip": str(source_ip) if source_ip is not None else None,
                "destination_ip": str(destination_ip) if destination_ip is not None else None,
                "process_name": str(process_name) if process_name is not None else None,
                "command_line": str(command_line) if command_line is not None else None,
                "message": message,
                "attributes": data,
            },
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
