import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

import pytest
from redis import Redis
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session

from app.integrations.registry import AdapterRegistry
from app.integrations.wazuh import WazuhAdapter
from app.models import Endpoint, Organization, SecurityEvent
from app.services.ingestion import IngestionService

pytestmark = pytest.mark.integration


@pytest.fixture()
def integration_url():
    value = os.getenv("INTEGRATION_DATABASE_URL")
    if not value:
        pytest.skip("INTEGRATION_DATABASE_URL is not configured")
    return value


def test_postgresql_rls_isolates_rows(integration_url) -> None:
    engine = create_engine(integration_url)
    org_a, org_b = uuid.uuid4(), uuid.uuid4()
    with Session(engine) as session:
        session.add_all(
            [
                Organization(id=org_a, name="RLS A", slug=f"rls-a-{org_a}"),
                Organization(id=org_b, name="RLS B", slug=f"rls-b-{org_b}"),
            ]
        )
        session.flush()
        session.execute(
            text("SELECT set_config('app.current_organization_id', :org, true)"),
            {"org": str(org_a)},
        )
        session.add(Endpoint(organization_id=org_a, hostname="a", agent_id="a", status="active"))
        session.flush()
        session.execute(
            text("SELECT set_config('app.current_organization_id', :org, true)"),
            {"org": str(org_b)},
        )
        session.add(Endpoint(organization_id=org_b, hostname="b", agent_id="b", status="active"))
        session.commit()
    with Session(engine) as session:
        session.execute(
            text("SELECT set_config('app.current_organization_id', :org, true)"),
            {"org": str(org_a)},
        )
        assert [item.hostname for item in session.scalars(select(Endpoint))] == ["a"]


def test_redis_distributed_lock() -> None:
    redis_url = os.getenv("INTEGRATION_REDIS_URL")
    if not redis_url:
        pytest.skip("INTEGRATION_REDIS_URL is not configured")
    redis = Redis.from_url(redis_url)
    first = redis.lock("integration-test-lock", timeout=10)
    second = redis.lock("integration-test-lock", timeout=10)
    assert first.acquire(blocking=False)
    assert not second.acquire(blocking=False)
    first.release()


def test_concurrent_ingestion_is_idempotent(integration_url) -> None:
    engine = create_engine(integration_url)
    organization_id = uuid.uuid4()
    with Session(engine) as session:
        session.add(
            Organization(
                id=organization_id, name="Concurrency", slug=f"concurrency-{organization_id}"
            )
        )
        session.commit()
    payload = {
        "id": f"concurrent-{uuid.uuid4()}",
        "timestamp": datetime.now(UTC).isoformat(),
        "agent": {"id": "concurrent-agent", "name": "concurrent-host"},
        "rule": {"level": 7, "description": "Concurrent test", "groups": ["test"]},
    }

    def ingest_once():
        with Session(engine, expire_on_commit=False) as session:
            session.execute(
                text("SELECT set_config('app.current_organization_id', :org, true)"),
                {"org": str(organization_id)},
            )
            return (
                IngestionService(session, AdapterRegistry([WazuhAdapter()]))
                .ingest(organization_id, "wazuh", payload)
                .duplicate
            )

    with ThreadPoolExecutor(max_workers=2) as executor:
        duplicates = list(executor.map(lambda _: ingest_once(), range(2)))
    assert sorted(duplicates) == [False, True]
    with Session(engine) as session:
        session.execute(
            text("SELECT set_config('app.current_organization_id', :org, true)"),
            {"org": str(organization_id)},
        )
        assert len(list(session.scalars(select(SecurityEvent)))) == 1
