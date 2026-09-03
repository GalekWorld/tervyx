import threading
import time

import httpx
import pytest

from app.integrations.oidc.client import OIDCClient
from app.integrations.resilience import (
    Bulkhead,
    CircuitBreaker,
    ConnectorBulkheadFull,
    ConnectorCircuitOpen,
    RetryPolicy,
)
from tests.test_identity_access import _oidc_provider


def test_retry_policy_caps_backoff_and_adds_bounded_jitter() -> None:
    policy = RetryPolicy(max_attempts=4, base_delay_seconds=1, max_delay_seconds=3)
    delays = [policy.delay(index) for index in range(5)]
    assert all(0 <= value <= 3.75 for value in delays)
    assert policy.delay(0, retry_after=100) <= 3.75


def test_circuit_breaker_opens_and_recovers() -> None:
    breaker = CircuitBreaker(failure_threshold=2, recovery_seconds=60)
    breaker.record_failure()
    breaker.record_failure()
    with pytest.raises(ConnectorCircuitOpen):
        breaker.before_call()
    # A successful half-open probe closes the circuit.
    breaker._opened_at = time.monotonic() - 61
    breaker.before_call()
    breaker.record_success()
    breaker.before_call()


def test_bulkhead_rejects_excess_concurrency() -> None:
    bulkhead = Bulkhead(limit=1, acquire_timeout=0)
    entered = threading.Event()
    release = threading.Event()

    def holder() -> None:
        with bulkhead.slot():
            entered.set()
            release.wait(timeout=1)

    thread = threading.Thread(target=holder)
    thread.start()
    assert entered.wait(timeout=1)
    with pytest.raises(ConnectorBulkheadFull):
        with bulkhead.slot():
            pass
    release.set()
    thread.join(timeout=1)


def test_oidc_retries_transient_failure_and_recovers() -> None:
    calls = []
    sleeps = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(503 if len(calls) == 1 else 200)

    client = OIDCClient(
        _oidc_provider(),
        "secret",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        sleep=sleeps.append,
    )
    response = client._request("GET", "https://issuer.example.test/health")
    assert response.status_code == 200
    assert len(calls) == 2
    assert len(sleeps) == 1
    client.close()
