"""Common synchronous resilience policy for external connectors."""

from __future__ import annotations

import secrets
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass


class ConnectorCircuitOpen(RuntimeError):
    """The connector is temporarily unavailable after repeated failures."""


class ConnectorBulkheadFull(RuntimeError):
    """The connector concurrency budget is exhausted."""


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 3
    base_delay_seconds: float = 0.5
    max_delay_seconds: float = 30.0
    jitter_ratio: float = 0.25

    def delay(self, retry_index: int, retry_after: float | None = None) -> float:
        exponential = min(
            self.max_delay_seconds,
            self.base_delay_seconds * (2**retry_index),
        )
        if retry_after is not None:
            exponential = min(self.max_delay_seconds, max(0.0, retry_after))
        jitter = exponential * self.jitter_ratio
        return max(0.0, secrets.SystemRandom().uniform(exponential - jitter, exponential + jitter))


class CircuitBreaker:
    def __init__(self, failure_threshold: int = 5, recovery_seconds: float = 30.0) -> None:
        self.failure_threshold = failure_threshold
        self.recovery_seconds = recovery_seconds
        self._failures = 0
        self._opened_at: float | None = None
        self._probe_in_flight = False
        self._lock = threading.Lock()

    def before_call(self) -> None:
        with self._lock:
            if self._opened_at is None:
                return
            if time.monotonic() - self._opened_at < self.recovery_seconds:
                raise ConnectorCircuitOpen("connector circuit is open")
            if self._probe_in_flight:
                raise ConnectorCircuitOpen("connector circuit is probing")
            self._probe_in_flight = True

    def record_success(self) -> None:
        with self._lock:
            self._failures = 0
            self._opened_at = None
            self._probe_in_flight = False

    def record_failure(self) -> None:
        with self._lock:
            self._failures += 1
            self._probe_in_flight = False
            if self._failures >= self.failure_threshold:
                self._opened_at = time.monotonic()


class Bulkhead:
    def __init__(self, limit: int = 20, acquire_timeout: float = 0.1) -> None:
        self._semaphore = threading.BoundedSemaphore(limit)
        self.acquire_timeout = acquire_timeout

    @contextmanager
    def slot(self) -> Iterator[None]:
        if not self._semaphore.acquire(timeout=self.acquire_timeout):
            raise ConnectorBulkheadFull("connector concurrency limit reached")
        try:
            yield
        finally:
            self._semaphore.release()


@dataclass
class ConnectorResilience:
    policy: RetryPolicy
    circuit_breaker: CircuitBreaker
    bulkhead: Bulkhead


_registry: dict[str, ConnectorResilience] = {}
_registry_lock = threading.Lock()


def get_connector_resilience(key: str, *, max_attempts: int) -> ConnectorResilience:
    """Return a process-local budget shared by calls to the same connector."""
    with _registry_lock:
        existing = _registry.get(key)
        if existing is not None:
            return existing
        created = ConnectorResilience(
            policy=RetryPolicy(max_attempts=max_attempts, base_delay_seconds=1.0),
            circuit_breaker=CircuitBreaker(),
            bulkhead=Bulkhead(),
        )
        _registry[key] = created
        return created
