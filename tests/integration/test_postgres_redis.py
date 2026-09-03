import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

import pytest
from redis import Redis
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError, ProgrammingError
from sqlalchemy.orm import Session

from app.core.database import set_tenant_context
from app.integrations.registry import AdapterRegistry
from app.integrations.wazuh import WazuhAdapter
from app.models import (
    AuditLedgerEntry,
    AuditLog,
    DeadLetterEvent,
    Endpoint,
    IdentityProvider,
    Incident,
    IncidentEnrichment,
    IntegrationAccount,
    IntegrationCheckpoint,
    Investigation,
    Organization,
    SecurityEvent,
)
from app.services.audit_ledger import AuditLedgerService
from app.services.endpoint_agent import EndpointAgentError, EndpointAgentService
from app.services.enrichment import IncidentEnrichmentService
from app.services.ingestion import IngestionService
from app.services.investigation import InvestigationService

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
        policies = session.execute(
            text(
                "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                "WHERE relname IN ('investigations', 'incident_enrichments')"
            )
        ).all()
        assert policies == [(True, True), (True, True)]


def test_endpoint_agent_heartbeat_requires_its_tenant_context(integration_url) -> None:
    engine = create_engine(integration_url)
    org_a, org_b = uuid.uuid4(), uuid.uuid4()
    with Session(engine, expire_on_commit=False) as session:
        session.add_all(
            [
                Organization(id=org_a, name="Agent RLS A", slug=f"agent-rls-a-{org_a}"),
                Organization(id=org_b, name="Agent RLS B", slug=f"agent-rls-b-{org_b}"),
            ]
        )
        session.flush()
        session.execute(
            text("SELECT set_config('app.current_organization_id', :org, true)"),
            {"org": str(org_a)},
        )
        endpoint = Endpoint(
            organization_id=org_a,
            hostname="agent-rls-a",
            agent_id=f"agent-rls-{org_a}",
            status="active",
        )
        session.add(endpoint)
        session.flush()
        enrolled, token = EndpointAgentService(session).enroll(org_a, endpoint.id, org_a)
        session.commit()
        EndpointAgentService(session).heartbeat(
            org_a, enrolled.identity_key, token, {"health": "ok"}, "1.0", None
        )
        with pytest.raises(EndpointAgentError):
            EndpointAgentService(session).heartbeat(
                org_b, enrolled.identity_key, token, {"health": "ok"}, "1.0", None
            )


def test_identity_provider_rls_isolates_tenants(integration_url) -> None:
    engine = create_engine(integration_url)
    org_a, org_b = uuid.uuid4(), uuid.uuid4()
    with Session(engine) as session:
        session.add_all(
            [
                Organization(id=org_a, name="OIDC RLS A", slug=f"oidc-rls-a-{org_a}"),
                Organization(id=org_b, name="OIDC RLS B", slug=f"oidc-rls-b-{org_b}"),
            ]
        )
        session.flush()
        for organization_id, name in ((org_a, "entra-a"), (org_b, "entra-b")):
            session.execute(
                text("SELECT set_config('app.current_organization_id', :org, true)"),
                {"org": str(organization_id)},
            )
            session.add(
                IdentityProvider(
                    organization_id=organization_id,
                    provider_type="entra",
                    name=name,
                    issuer=f"https://login.microsoftonline.com/{organization_id}/v2.0",
                    client_id=str(uuid.uuid4()),
                    client_secret_reference=f"vault://tenants/{organization_id}/oidc/entra",
                    scopes=["openid"],
                    allowed_redirect_uris=["https://soc.example.test/callback"],
                    provider_tenant_id=str(organization_id),
                )
            )
            session.flush()
        session.commit()
    with Session(engine) as session:
        session.execute(
            text("SELECT set_config('app.current_organization_id', :org, true)"),
            {"org": str(org_a)},
        )
        assert [item.name for item in session.scalars(select(IdentityProvider))] == ["entra-a"]


def test_postgresql_audit_ledger_is_rls_scoped_and_append_only(integration_url) -> None:
    engine = create_engine(integration_url)
    organization_id = uuid.uuid4()
    with Session(engine) as session:
        session.add(
            Organization(id=organization_id, name="Ledger", slug=f"ledger-{organization_id}")
        )
        session.flush()
        set_tenant_context(session, organization_id)
        session.add(
            AuditLog(
                organization_id=organization_id,
                actor_type="system",
                actor_id="test",
                action="ledger.test",
                resource_type="test",
                resource_id=None,
                details={},
            )
        )
        session.commit()
        assert AuditLedgerService(session).verify(organization_id).valid
        entry = session.scalar(select(AuditLedgerEntry))
        assert entry is not None
        other_organization_id = uuid.uuid4()
        set_tenant_context(session, other_organization_id)
        assert session.scalar(select(AuditLedgerEntry)) is None
        set_tenant_context(session, organization_id)
        with pytest.raises(DBAPIError):
            session.execute(
                text("UPDATE audit_ledger_entries SET entry_hash = '0' WHERE id = :id"),
                {"id": entry.id},
            )
        session.rollback()
        set_tenant_context(session, organization_id)
        with pytest.raises(DBAPIError):
            session.execute(
                text("DELETE FROM audit_ledger_entries WHERE id = :id"),
                {"id": entry.id},
            )
        session.rollback()
        assert (
            session.scalar(
                text(
                    "SELECT 1 FROM pg_trigger "
                    "WHERE tgname = 'audit_ledger_no_update' "
                    "AND tgrelid = 'audit_ledger_entries'::regclass"
                )
            )
            == 1
        )


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


def test_incident_enrichment_uses_rls_and_concurrent_replays_converge(integration_url) -> None:
    """Exercise the PostgreSQL conflict path, not the SQLite test fallback."""
    engine = create_engine(integration_url)
    org_a, org_b = uuid.uuid4(), uuid.uuid4()
    with Session(engine) as session:
        session.add_all(
            [
                Organization(id=org_a, name="Enrichment A", slug=f"enrichment-a-{org_a}"),
                Organization(id=org_b, name="Enrichment B", slug=f"enrichment-b-{org_b}"),
            ]
        )
        session.flush()
        session.execute(
            text("SELECT set_config('app.current_organization_id', :org, true)"),
            {"org": str(org_a)},
        )
        endpoint = Endpoint(
            organization_id=org_a,
            hostname="enrichment-a",
            agent_id=f"enrichment-{org_a}",
            status="active",
        )
        session.add(endpoint)
        session.flush()
        incident = Incident(
            organization_id=org_a,
            title="Concurrent enrichment",
            severity=8,
            priority="high",
            status="open",
            confidence=0.9,
            occurred_at=datetime.now(UTC),
            first_seen=datetime.now(UTC),
            last_seen=datetime.now(UTC),
            correlation_key=f"enrichment:{endpoint.id}",
            affected_endpoint_ids=[str(endpoint.id)],
            affected_users=[],
            source_ips=["203.0.113.4"],
            destination_ips=[],
            mitre_attack=[],
            evidence={"origin": "integration-test"},
            timeline=[],
            sla_due_at=datetime.now(UTC),
        )
        session.add(incident)
        session.flush()
        incident_id = incident.id
        session.commit()

    def enrich_once() -> int:
        with Session(engine) as session:
            session.execute(
                text("SELECT set_config('app.current_organization_id', :org, true)"),
                {"org": str(org_a)},
            )
            current = session.scalar(select(Incident).where(Incident.id == incident_id))
            assert current is not None
            result = IncidentEnrichmentService(session, org_a).enrich(current)
            session.commit()
            return result.created_count

    with ThreadPoolExecutor(max_workers=2) as executor:
        created = list(executor.map(lambda _: enrich_once(), range(2)))
    assert sum(created) == 3  # assets, IOCs and context converge on one row each.

    with Session(engine) as session:
        session.execute(
            text("SELECT set_config('app.current_organization_id', :org, true)"),
            {"org": str(org_a)},
        )
        rows = list(session.scalars(select(IncidentEnrichment)))
        assert {row.enrichment_type for row in rows} == {"assets", "iocs", "context"}
        assert len(rows) == 3
        session.execute(
            text("SELECT set_config('app.current_organization_id', :org, true)"),
            {"org": str(org_b)},
        )
        assert list(session.scalars(select(IncidentEnrichment))) == []


def test_investigation_engine_is_idempotent_and_rls_scoped(integration_url) -> None:
    engine = create_engine(integration_url)
    org_a, org_b = uuid.uuid4(), uuid.uuid4()
    with Session(engine) as session:
        session.add_all(
            [
                Organization(id=org_a, name="Investigation A", slug=f"investigation-a-{org_a}"),
                Organization(id=org_b, name="Investigation B", slug=f"investigation-b-{org_b}"),
            ]
        )
        session.flush()
        session.execute(
            text("SELECT set_config('app.current_organization_id', :org, true)"),
            {"org": str(org_a)},
        )
        incident = Incident(
            organization_id=org_a,
            title="Investigation",
            severity=7,
            priority="high",
            status="open",
            confidence=0.8,
            occurred_at=datetime.now(UTC),
            first_seen=datetime.now(UTC),
            last_seen=datetime.now(UTC),
            affected_endpoint_ids=[],
            affected_users=[],
            source_ips=["198.51.100.10"],
            destination_ips=[],
            mitre_attack=[],
            evidence={},
            timeline=[],
            sla_due_at=datetime.now(UTC),
        )
        session.add(incident)
        session.flush()
        incident_id = incident.id
        session.commit()

    def create_once() -> uuid.UUID:
        with Session(engine) as session:
            session.execute(
                text("SELECT set_config('app.current_organization_id', :org, true)"),
                {"org": str(org_a)},
            )
            current = session.scalar(select(Incident).where(Incident.id == incident_id))
            assert current is not None
            result = InvestigationService(session, org_a).create_from_incident(current)
            result_id = result.id
            session.commit()
            return result_id

    with ThreadPoolExecutor(max_workers=2) as executor:
        ids = list(executor.map(lambda _: create_once(), range(2)))
    assert ids[0] == ids[1]

    with Session(engine) as session:
        session.execute(
            text("SELECT set_config('app.current_organization_id', :org, true)"),
            {"org": str(org_a)},
        )
        assert len(list(session.scalars(select(Investigation)))) == 1
        assert (
            session.scalar(
                select(text("count(*)"))
                .select_from(AuditLog)
                .where(AuditLog.action == "investigation.created")
            )
            == 1
        )
        session.execute(
            text("SELECT set_config('app.current_organization_id', :org, true)"),
            {"org": str(org_b)},
        )
        assert list(session.scalars(select(Investigation))) == []


def test_tenant_scoped_foreign_keys_reject_cross_tenant_references(integration_url) -> None:
    engine = create_engine(integration_url)
    org_a, org_b = uuid.uuid4(), uuid.uuid4()
    with Session(engine) as session:
        session.add_all(
            [
                Organization(id=org_a, name="Foreign key A", slug=f"fk-a-{org_a}"),
                Organization(id=org_b, name="Foreign key B", slug=f"fk-b-{org_b}"),
            ]
        )
        session.flush()
        for organization_id, agent_id in ((org_a, "fk-a"), (org_b, "fk-b")):
            session.execute(
                text("SELECT set_config('app.current_organization_id', :org, true)"),
                {"org": str(organization_id)},
            )
            session.add(
                Endpoint(
                    organization_id=organization_id,
                    hostname=agent_id,
                    agent_id=agent_id,
                    status="active",
                )
            )
            session.flush()
        session.execute(
            text("SELECT set_config('app.current_organization_id', :org, true)"),
            {"org": str(org_b)},
        )
        incident = Incident(
            organization_id=org_b,
            title="Tenant B",
            severity=5,
            priority="medium",
            status="open",
            confidence=0.5,
            occurred_at=datetime.now(UTC),
            first_seen=datetime.now(UTC),
            last_seen=datetime.now(UTC),
            affected_endpoint_ids=[],
            affected_users=[],
            source_ips=[],
            destination_ips=[],
            mitre_attack=[],
            evidence={},
            timeline=[],
            sla_due_at=datetime.now(UTC),
        )
        session.add(incident)
        session.flush()
        endpoint_b = session.scalar(
            select(Endpoint).where(Endpoint.organization_id == org_b, Endpoint.agent_id == "fk-b")
        )
        assert endpoint_b is not None
        integration_b = IntegrationAccount(
            organization_id=org_b,
            integration_type="wazuh",
            name="fk-b-integration",
            base_url="https://wazuh.example.test",
            credential_reference=f"env://FK_B_{org_b}",
        )
        session.add(integration_b)
        session.flush()
        incident_b_id = incident.id
        endpoint_b_id = endpoint_b.id
        integration_b_id = integration_b.id
        session.commit()

    with Session(engine) as session:
        session.execute(
            text("SELECT set_config('app.current_organization_id', :org, true)"),
            {"org": str(org_a)},
        )
        session.add(
            SecurityEvent(
                organization_id=org_a,
                endpoint_id=endpoint_b_id,
                source="hardening",
                external_id=f"cross-event-{uuid.uuid4()}",
                event_type="test",
                severity=1,
                occurred_at=datetime.now(UTC),
                raw_payload={},
                normalized_data={},
            )
        )
        with pytest.raises((IntegrityError, ProgrammingError)):
            session.flush()
        session.rollback()

        session.add(
            IntegrationCheckpoint(
                organization_id=org_a,
                integration_account_id=integration_b_id,
                stream="alerts",
            )
        )
        with pytest.raises((IntegrityError, ProgrammingError)):
            session.flush()
        session.rollback()

        session.add(
            DeadLetterEvent(
                organization_id=org_a,
                integration_account_id=integration_b_id,
                payload={},
                error="cross-tenant integrity check",
                attempts=1,
                first_failed_at=datetime.now(UTC),
                last_failed_at=datetime.now(UTC),
                status="pending",
            )
        )
        with pytest.raises((IntegrityError, ProgrammingError)):
            session.flush()
        session.rollback()

        session.execute(
            text("SELECT set_config('app.current_organization_id', :org, true)"),
            {"org": str(org_a)},
        )
        session.add(
            Investigation(
                organization_id=org_a,
                incident_id=incident_b_id,
                risk_score=1,
                classification="low",
                confidence=0.1,
                evidence=[],
                timeline=[],
                explanation="cross-tenant integrity check",
                recommended_actions=[],
                status="completed",
            )
        )
        with pytest.raises((IntegrityError, ProgrammingError)):
            session.flush()
