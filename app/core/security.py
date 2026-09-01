from typing import Any

SENSITIVE_KEYS = {"password", "token", "secret", "api_key", "authorization", "key"}


def sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if str(key).lower() in SENSITIVE_KEYS else sanitize(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    return value


def safe_error(exc: Exception) -> str:
    text = str(exc)
    return text[:1000]
