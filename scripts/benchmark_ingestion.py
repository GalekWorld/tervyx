import time
import uuid
from datetime import UTC, datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.core.database import Base
from app.integrations.registry import AdapterRegistry
from app.integrations.wazuh import WazuhAdapter
from app.models import Organization
from app.services.ingestion import IngestionService


def main(count: int = 10_000) -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    organization_id = uuid.uuid4()
    started = time.perf_counter()
    with Session(engine, expire_on_commit=False) as session:
        session.add(Organization(id=organization_id, name="Benchmark", slug="benchmark"))
        session.commit()
        service = IngestionService(session, AdapterRegistry([WazuhAdapter()]))
        for index in range(count):
            service.ingest(
                organization_id,
                "wazuh",
                {
                    "id": f"benchmark-{index}",
                    "timestamp": datetime.now(UTC).isoformat(),
                    "agent": {"id": f"agent-{index % 100}", "name": f"host-{index % 100}"},
                    "rule": {"level": 5, "description": "Benchmark event", "groups": ["benchmark"]},
                },
            )
    elapsed = time.perf_counter() - started
    print(f"events={count} seconds={elapsed:.3f} events_per_second={count / elapsed:.1f}")


if __name__ == "__main__":
    main()
