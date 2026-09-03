import uuid
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import set_tenant_context
from app.detection import DetectionEngine
from app.integrations.base import NormalizedSecurityRecord
from app.integrations.registry import AdapterRegistry
from app.models import Alert, AuditLog, Endpoint, SecurityEvent
from app.repositories import SecurityRepository
from app.schemas.entities import AlertRead, EndpointRead, SecurityEventRead
from app.schemas.ingestion import IngestResult
from app.services.quotas import QuotaService, payload_byte_count


@dataclass(slots=True)
class BatchIngestResult:
    submitted_count: int
    processed_count: int = 0
    duplicate_count: int = 0
    failed_count: int = 0
    failures: list[tuple[dict, str]] = field(default_factory=list)


class IngestionService:
    def __init__(self, session: Session, registry: AdapterRegistry) -> None:
        self.session = session
        self.registry = registry
        self.detection_engine = DetectionEngine()

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
            QuotaService(self.session).reserve_ingestion(
                organization_id, events=1, byte_count=payload_byte_count(payload)
            )
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

    def ingest_batch(
        self, organization_id: uuid.UUID, source: str, payloads: list[dict]
    ) -> BatchIngestResult:
        """Normalize and persist a page in one transaction.

        Malformed records are reported to the caller for DLQ handling while valid
        records retain a single atomic commit.  Unique constraints remain the
        final idempotency guard when concurrent workers overlap.
        """
        outcome = BatchIngestResult(submitted_count=len(payloads))
        if not payloads:
            return outcome
        set_tenant_context(self.session, organization_id)
        adapter = self.registry.get(source)
        records: list[tuple[NormalizedSecurityRecord, dict]] = []
        for payload in payloads:
            try:
                records.append((adapter.normalize(payload), payload))
            except Exception as exc:  # Adapter boundary: caller DLQs individual malformed input.
                outcome.failed_count += 1
                outcome.failures.append((payload, type(exc).__name__))
        if not records:
            return outcome

        unique_records: list[tuple[NormalizedSecurityRecord, dict]] = []
        batch_keys: set[tuple[str, str]] = set()
        for record, payload in records:
            key = (record.source, record.event.external_id)
            if key in batch_keys:
                outcome.duplicate_count += 1
                continue
            batch_keys.add(key)
            unique_records.append((record, payload))

        existing_keys = set(
            self.session.execute(
                select(SecurityEvent.source, SecurityEvent.external_id).where(
                    SecurityEvent.organization_id == organization_id,
                    SecurityEvent.source == source,
                    SecurityEvent.external_id.in_(
                        [record.event.external_id for record, _ in unique_records]
                    ),
                )
            ).all()
        )
        new_records = [
            (record, payload)
            for record, payload in unique_records
            if (record.source, record.event.external_id) not in existing_keys
        ]
        outcome.duplicate_count += len(unique_records) - len(new_records)
        if not new_records:
            return outcome

        try:
            quota_service = QuotaService(self.session)
            quota_service.reserve_ingestion(
                organization_id,
                events=len(new_records),
                byte_count=sum(payload_byte_count(payload) for _, payload in new_records),
            )
            agent_ids = {record.endpoint.agent_id for record, _ in new_records}
            endpoints = {
                endpoint.agent_id: endpoint
                for endpoint in self.session.scalars(
                    select(Endpoint).where(
                        Endpoint.organization_id == organization_id,
                        Endpoint.agent_id.in_(agent_ids),
                    )
                )
            }
            for record, _ in new_records:
                endpoint = endpoints.get(record.endpoint.agent_id)
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
                    endpoints[record.endpoint.agent_id] = endpoint
                    self.session.add(endpoint)
                else:
                    endpoint.hostname = record.endpoint.hostname
                    endpoint.operating_system = (
                        record.endpoint.operating_system or endpoint.operating_system
                    )
                    endpoint.ip_address = record.endpoint.ip_address or endpoint.ip_address
                    endpoint.status = record.endpoint.status
                    endpoint.last_seen = record.endpoint.last_seen
            self.session.flush()
            for record, _ in new_records:
                endpoint = endpoints[record.endpoint.agent_id]
                event = SecurityEvent(
                    organization_id=organization_id,
                    endpoint_id=endpoint.id,
                    source=record.source,
                    external_id=record.event.external_id,
                    event_type=record.event.event_type,
                    severity=record.event.severity,
                    occurred_at=record.event.occurred_at,
                    raw_payload=record.event.raw_payload,
                    normalized_data=record.event.normalized_data,
                )
                self.session.add(event)
                self.session.flush()
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
                for detection_alert in self.detection_engine.evaluate(self.session, event):
                    self.session.add(detection_alert)
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
            outcome.processed_count = len(new_records)
            return outcome
        except IntegrityError:
            self.session.rollback()
            # A competing worker may have won a subset. Safe per-record retries
            # preserve the unique constraint as the canonical deduplication key.
            for _record, payload in new_records:
                try:
                    result = self.ingest(organization_id, source, payload)
                    if result.duplicate:
                        outcome.duplicate_count += 1
                    else:
                        outcome.processed_count += 1
                except Exception as exc:
                    outcome.failed_count += 1
                    outcome.failures.append((payload, type(exc).__name__))
            return outcome

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
            normalized_data=record.event.normalized_data,
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

        detected_alerts = self.detection_engine.evaluate(self.session, event)
        for detected_alert in detected_alerts:
            self.session.add(detected_alert)
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
