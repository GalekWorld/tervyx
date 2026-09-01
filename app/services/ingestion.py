import uuid

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import set_tenant_context
from app.integrations.base import NormalizedSecurityRecord
from app.integrations.registry import AdapterRegistry
from app.models import Alert, AuditLog, Endpoint, SecurityEvent
from app.repositories import SecurityRepository
from app.schemas.entities import AlertRead, EndpointRead, SecurityEventRead
from app.schemas.ingestion import IngestResult


class IngestionService:
    def __init__(self, session: Session, registry: AdapterRegistry) -> None:
        self.session = session
        self.registry = registry

    def ingest(self, organization_id: uuid.UUID, source: str, payload: dict) -> IngestResult:
        # SET LOCAL is transaction-scoped, so every service entry point restores
        # the tenant context independently of the caller or a prior commit.
        set_tenant_context(self.session, organization_id)
        adapter = self.registry.get(source)
        record = adapter.normalize(payload)
        repository = SecurityRepository(self.session, organization_id)

        existing_event = repository.get_event_by_external_id(
            record.source, record.event.external_id
        )
        if existing_event is not None:
            return self._duplicate_result(repository, existing_event)

        try:
            return self._persist_new(organization_id, record, repository)
        except IntegrityError:
            # Either the endpoint or event unique constraint may win a race.
            # PostgreSQL waits for the competing transaction before raising,
            # so after rollback the committed event can be loaded safely.
            self.session.rollback()
            set_tenant_context(self.session, organization_id)
            repository = SecurityRepository(self.session, organization_id)
            concurrent_event = repository.get_event_by_external_id(
                record.source, record.event.external_id
            )
            if concurrent_event is None:
                raise
            return self._duplicate_result(repository, concurrent_event)

    def _persist_new(
        self,
        organization_id: uuid.UUID,
        record: NormalizedSecurityRecord,
        repository: SecurityRepository,
    ) -> IngestResult:

        endpoint = repository.get_endpoint_by_agent(record.endpoint.agent_id)
        if endpoint is None:
            endpoint = Endpoint(
                organization_id=organization_id,
                agent_id=record.endpoint.agent_id,
                hostname=record.endpoint.hostname,
                operating_system=record.endpoint.operating_system,
                ip_address=record.endpoint.ip_address,
                status=record.endpoint.status,
                last_seen=record.endpoint.last_seen,
            )
            self.session.add(endpoint)
            self.session.flush()
        else:
            endpoint.hostname = record.endpoint.hostname
            endpoint.operating_system = (
                record.endpoint.operating_system or endpoint.operating_system
            )
            endpoint.ip_address = record.endpoint.ip_address or endpoint.ip_address
            endpoint.status = record.endpoint.status
            endpoint.last_seen = record.endpoint.last_seen

        event = SecurityEvent(
            organization_id=organization_id,
            endpoint_id=endpoint.id,
            source=record.source,
            external_id=record.event.external_id,
            event_type=record.event.event_type,
            severity=record.event.severity,
            occurred_at=record.event.occurred_at,
            raw_payload=record.event.raw_payload,
        )
        self.session.add(event)
        self.session.flush()

        alert = None
        if record.alert is not None:
            alert = Alert(
                organization_id=organization_id,
                endpoint_id=endpoint.id,
                source=record.source,
                external_id=record.alert.external_id,
                title=record.alert.title,
                description=record.alert.description,
                severity=record.alert.severity,
                status=record.alert.status,
                occurred_at=record.alert.occurred_at,
            )
            alert.security_events.append(event)
            self.session.add(alert)
            self.session.flush()

        self.session.add(
            AuditLog(
                organization_id=organization_id,
                actor_type="integration",
                actor_id=record.source,
                action="security_event.ingested",
                resource_type="security_event",
                resource_id=str(event.id),
                details={"source": record.source, "external_id": record.event.external_id},
            )
        )
        self.session.commit()

        return IngestResult(
            endpoint=EndpointRead.model_validate(endpoint),
            event=SecurityEventRead.model_validate(event),
            alert=AlertRead.model_validate(alert) if alert else None,
            duplicate=False,
            organization_id=organization_id,
        )

    def _duplicate_result(
        self, repository: SecurityRepository, event: SecurityEvent
    ) -> IngestResult:
        endpoint = repository.get_endpoint(event.endpoint_id)
        alert = repository.get_alert_by_external_id(event.source, event.external_id)
        if endpoint is None:  # Defensive: protected by foreign keys.
            raise RuntimeError("Stored event references a missing endpoint")
        return IngestResult(
            endpoint=EndpointRead.model_validate(endpoint),
            event=SecurityEventRead.model_validate(event),
            alert=AlertRead.model_validate(alert) if alert else None,
            duplicate=True,
            organization_id=repository.organization_id,
        )
