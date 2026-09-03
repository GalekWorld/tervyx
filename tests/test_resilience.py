from datetime import UTC, datetime

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.integrations.registry import AdapterRegistry
from app.integrations.wazuh import WazuhAdapter
from app.models import SecurityEvent, SecurityEventArchive, TenantQuota
from app.services.archive import FilesystemObjectStorage, RetentionService
from app.services.fair_queue import BackpressureError, TenantFairQueue
from app.services.ingestion import IngestionService
from tests.conftest import OTHER_ORG_ID, TEST_ORG_ID


class FakeRedis:
    def __init__(self) -> None:
        self.values: dict[str, list[str]] = {}
        self.sets: dict[str, set[str]] = {}

    def pipeline(self):
        return self

    def rpush(self, key, value):
        self.values.setdefault(key, []).append(value)
        return len(self.values[key])

    def llen(self, key):
        return len(self.values.get(key, []))

    def execute(self):
        # TenantFairQueue only needs rpush/llen results in this deterministic fake.
        return [0, len(next(iter(self.values.values()), []))]

    def rpop(self, key):
        return self.values.get(key, []).pop() if self.values.get(key) else None

    def sadd(self, key, value):
        values = self.sets.setdefault(key, set())
        before = len(values)
        values.add(value)
        return int(len(values) != before)

    def lpop(self, key):
        return self.values.get(key, []).pop(0) if self.values.get(key) else None

    def srem(self, key, value):
        self.sets.get(key, set()).discard(value)


def test_fair_queue_round_robins_and_enforces_per_tenant_backpressure() -> None:
    queue = TenantFairQueue(FakeRedis())
    queue.enqueue(TEST_ORG_ID, {"n": 1}, max_depth=2)
    queue.enqueue(TEST_ORG_ID, {"n": 2}, max_depth=2)
    queue.enqueue(OTHER_ORG_ID, {"n": 3}, max_depth=2)
    first_pass = queue.dequeue_fair(2)
    assert [item.organization_id for item in first_pass] == [TEST_ORG_ID, OTHER_ORG_ID]
    with pytest.raises(BackpressureError):
        queue.enqueue(TEST_ORG_ID, {"n": 4}, max_depth=1)


def test_archive_writes_before_deleting_hot_events(
    session: Session, wazuh_payload: dict, tmp_path
) -> None:
    payload = {**wazuh_payload, "timestamp": "2020-01-01T00:00:00.000Z"}
    IngestionService(session, AdapterRegistry([WazuhAdapter()])).ingest(
        TEST_ORG_ID, "wazuh", payload
    )
    result = RetentionService(session, FilesystemObjectStorage(str(tmp_path))).archive_due(
        TEST_ORG_ID, now=datetime.now(UTC)
    )
    assert result.archived_events == 1
    assert session.scalar(select(func.count()).select_from(SecurityEvent)) == 0
    archive = session.scalar(select(SecurityEventArchive))
    assert archive is not None
    assert (tmp_path / archive.storage_key).exists()


def test_quota_never_mixes_tenant_usage(session: Session, wazuh_payload: dict) -> None:
    quota = TenantQuota(
        organization_id=TEST_ORG_ID,
        max_events_per_day=1,
        max_jobs_per_minute=1,
        max_api_requests_per_minute=1,
        max_storage_bytes=10_000,
        max_queue_depth=1,
        enabled=True,
    )
    session.add(quota)
    session.commit()
    service = IngestionService(session, AdapterRegistry([WazuhAdapter()]))
    service.ingest(TEST_ORG_ID, "wazuh", wazuh_payload)
    other = {**wazuh_payload, "id": "other-tenant-event"}
    assert service.ingest(OTHER_ORG_ID, "wazuh", other).duplicate is False
