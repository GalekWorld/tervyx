from app.core.observability import _sentry_before_send


def test_sentry_event_redacts_request_material_and_secrets() -> None:
    event = {
        "request": {
            "headers": {"Authorization": "Bearer eyJx.eyJx.eyJx"},
            "cookies": {"session": "secret"},
            "data": {"password": "do-not-send"},
            "query_string": "email=person@example.test",
        },
        "extra": {"token": "sensitive", "email": "person@example.test"},
    }
    scrubbed = _sentry_before_send(event, {})
    assert scrubbed["request"]["headers"] == "[REDACTED]"
    assert scrubbed["request"]["data"] == "[REDACTED]"
    assert scrubbed["extra"]["token"] == "[REDACTED]"
    assert scrubbed["extra"]["email"] == "[REDACTED]"
