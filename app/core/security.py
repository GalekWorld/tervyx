import re
from typing import Any

SENSITIVE_KEYS = {"password", "token", "secret", "api_key", "authorization", "key"}
JWT_PATTERN = re.compile(r"(?:Bearer\s+)?eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")


def _sensitive_key(value: object) -> bool:
    key = str(value).lower()
    return key in SENSITIVE_KEYS or any(
        key.endswith(f"_{suffix}")
        for suffix in ("password", "token", "secret", "api_key", "authorization", "key")
    )


def sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if _sensitive_key(key) else sanitize(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    if isinstance(value, str):
        return JWT_PATTERN.sub("[REDACTED]", value)
    return value


def safe_error(exc: Exception) -> str:
    text = str(exc)
    return text[:1000]
