import argparse
import json
import time
import uuid
from datetime import UTC, datetime
from typing import cast

from redis import Redis
from sqlalchemy import delete, func, select, text

from app.core.auth import create_worker_token
from app.core.config import get_settings
from app.core.database import SessionLocal, set_tenant_context
from app.models import IntegrationAccount, Organization, SecurityEvent
from app.workers.tasks import process_security_event


def percentile(values: list[float], probability: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[min(round((len(ordered) - 1) * probability), len(ordered) - 1)]


def main() -> None:
    parser = argparse.ArgumentParser(description="Celery/PostgreSQL ingestion benchmark")
    parser.add_argument("--count", type=int, required=True)
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument("--keep-data", action="store_true")
    args = parser.parse_args()
    if args.count < 1 or args.count > 1_000_000:
        parser.error("count must be between 1 and 1,000,000")

    run_id = uuid.uuid4().hex
    organization_id = uuid.uuid4()
    account_id = uuid.uuid4()
    settings = get_settings()
    redis = Redis.from_url(settings.celery_broker_url)
    ok_key = f"benchmark:{run_id}:ok"
    failed_key = f"benchmark:{run_id}:failed"
    redis.delete(ok_key, failed_key)

    with SessionLocal() as session:
        session.add(Organization(id=organization_id, name="Benchmark", slug=f"bench-{run_id}"))
        session.flush()
        set_tenant_context(session, organization_id)
        session.add(
            IntegrationAccount(
                id=account_id,
                organization_id=organization_id,
                integration_type="wazuh",
                name=f"benchmark-{run_id}",
                base_url="https://benchmark.invalid",
                credential_reference="env://BENCHMARK_UNUSED",
                enabled=True,
                status="configured",
            )
        )
        session.commit()

    token = create_worker_token(organization_id, account_id)
    started = time.monotonic()
    enqueued = time.time()
    for index in range(args.count):
        payload = {
            "id": f"bench-{run_id}-{index}",
            "timestamp": datetime.now(UTC).isoformat(),
            "agent": {
                "id": f"agent-{index % 1000:04d}",
                "name": f"benchmark-endpoint-{index % 1000:04d}",
                "ip": f"198.51.{(index // 254) % 255}.{index % 254 + 1}",
                "os": {"name": "Linux"},
            },
            "rule": {
                "id": "100001",
                "level": 7,
                "description": "Reproducible benchmark event",
                "groups": ["benchmark"],
            },
            "full_log": "Synthetic non-sensitive benchmark event",
            "_benchmark_run_id": run_id,
            "_benchmark_enqueued_at": enqueued,
        }
        process_security_event.delay(str(account_id), payload, token)

    queue_depth_max = cast(int, redis.llen("celery"))
    blocked_locks_max = 0
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        completed = cast(int, redis.llen(ok_key)) + cast(int, redis.llen(failed_key))
        queue_depth_max = max(queue_depth_max, cast(int, redis.llen("celery")))
        with SessionLocal() as session:
            blocked_locks = session.scalar(text("SELECT count(*) FROM pg_locks WHERE NOT granted"))
            blocked_locks_max = max(blocked_locks_max, int(blocked_locks or 0))
        if completed >= args.count:
            break
        time.sleep(0.5)

    duration = time.monotonic() - started
    latencies = [float(value) for value in cast(list[bytes], redis.lrange(ok_key, 0, -1))]
    failures = cast(int, redis.llen(failed_key))
    with SessionLocal() as session:
        set_tenant_context(session, organization_id)
        persisted = int(
            session.scalar(
                select(func.count(SecurityEvent.id)).where(
                    SecurityEvent.organization_id == organization_id
                )
            )
            or 0
        )

    report = {
        "run_id": run_id,
        "requested": args.count,
        "persisted": persisted,
        "errors": failures,
        "duration_seconds": round(duration, 3),
        "events_per_second": round(persisted / duration, 2) if duration else 0,
        "latency_ms": {
            "p50": round(percentile(latencies, 0.50), 3),
            "p95": round(percentile(latencies, 0.95), 3),
            "p99": round(percentile(latencies, 0.99), 3),
        },
        "queue_depth_max": queue_depth_max,
        "blocked_db_locks_max": blocked_locks_max,
        "timed_out": len(latencies) + failures < args.count,
    }
    print(json.dumps(report, sort_keys=True))

    redis.delete(ok_key, failed_key)
    if not args.keep_data:
        with SessionLocal() as session:
            session.execute(delete(Organization).where(Organization.id == organization_id))
            session.commit()


if __name__ == "__main__":
    main()
