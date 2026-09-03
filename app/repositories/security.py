import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.models import (
    Alert,
    AlertGroup,
    AlertGroupHistory,
    Endpoint,
    Incident,
    IncidentEnrichment,
    IncidentHistory,
    Investigation,
    SecurityEvent,
)


class SecurityRepository:
    """Tenant-scoped access to SOC entities.

    An organization identifier is mandatory at construction time so callers cannot
    accidentally issue an unscoped query through this repository.
    """

    def __init__(self, session: Session, organization_id: uuid.UUID) -> None:
        self.session = session
        self.organization_id = organization_id

    def list_endpoints(self) -> list[Endpoint]:
        return list(
            self.session.scalars(
                select(Endpoint)
                .where(Endpoint.organization_id == self.organization_id)
                .order_by(Endpoint.hostname)
            )
        )

    def page_endpoints(self, page: int, page_size: int, *, status: str | None = None):
        statement = select(Endpoint).where(Endpoint.organization_id == self.organization_id)
        if status:
            statement = statement.where(Endpoint.status == status)
        return self._page(statement.order_by(Endpoint.hostname), page, page_size)

    def page_events(self, page: int, page_size: int, **filters):
        statement = select(SecurityEvent).where(
            SecurityEvent.organization_id == self.organization_id
        )
        statement = self._event_filters(statement, SecurityEvent, filters)
        return self._page(statement.order_by(SecurityEvent.occurred_at.desc()), page, page_size)

    def page_alerts(self, page: int, page_size: int, **filters):
        statement = select(Alert).where(Alert.organization_id == self.organization_id)
        statement = self._event_filters(statement, Alert, filters)
        if filters.get("status"):
            statement = statement.where(Alert.status == filters["status"])
        return self._page(statement.order_by(Alert.occurred_at.desc()), page, page_size)

    def _event_filters(self, statement, model, filters):
        if filters.get("severity") is not None:
            statement = statement.where(model.severity == filters["severity"])
        if filters.get("source"):
            statement = statement.where(model.source == filters["source"])
        if filters.get("endpoint_id"):
            statement = statement.where(model.endpoint_id == filters["endpoint_id"])
        if filters.get("date_from"):
            statement = statement.where(model.occurred_at >= filters["date_from"])
        if filters.get("date_to"):
            statement = statement.where(model.occurred_at <= filters["date_to"])
        return statement

    def _page(self, statement, page: int, page_size: int):
        total = self.session.scalar(select(func.count()).select_from(statement.subquery())) or 0
        items = list(
            self.session.scalars(statement.offset((page - 1) * page_size).limit(page_size))
        )
        return items, total

    def get_endpoint(self, entity_id: uuid.UUID) -> Endpoint | None:
        return self.session.scalar(
            select(Endpoint).where(
                Endpoint.id == entity_id,
                Endpoint.organization_id == self.organization_id,
            )
        )

    def list_alerts(self) -> list[Alert]:
        return list(
            self.session.scalars(
                select(Alert)
                .where(Alert.organization_id == self.organization_id)
                .order_by(Alert.occurred_at.desc())
            )
        )

    def get_alert(self, entity_id: uuid.UUID) -> Alert | None:
        return self.session.scalar(
            select(Alert).where(
                Alert.id == entity_id, Alert.organization_id == self.organization_id
            )
        )

    def list_alert_groups(self) -> list[AlertGroup]:
        return list(
            self.session.scalars(
                select(AlertGroup)
                .options(selectinload(AlertGroup.alerts))
                .where(AlertGroup.organization_id == self.organization_id)
                .order_by(AlertGroup.last_seen.desc())
            )
        )

    def get_alert_group(self, entity_id: uuid.UUID) -> AlertGroup | None:
        return self.session.scalar(
            select(AlertGroup)
            .options(selectinload(AlertGroup.alerts))
            .where(AlertGroup.id == entity_id, AlertGroup.organization_id == self.organization_id)
        )

    def alert_group_history(self, entity_id: uuid.UUID) -> list[AlertGroupHistory]:
        return list(
            self.session.scalars(
                select(AlertGroupHistory)
                .where(
                    AlertGroupHistory.alert_group_id == entity_id,
                    AlertGroupHistory.organization_id == self.organization_id,
                )
                .order_by(AlertGroupHistory.created_at)
            )
        )

    def list_incidents(self) -> list[Incident]:
        return list(
            self.session.scalars(
                select(Incident)
                .options(selectinload(Incident.alerts), selectinload(Incident.alert_groups))
                .where(Incident.organization_id == self.organization_id)
                .order_by(Incident.occurred_at.desc())
            )
        )

    def get_incident(self, entity_id: uuid.UUID) -> Incident | None:
        return self.session.scalar(
            select(Incident)
            .options(selectinload(Incident.alerts), selectinload(Incident.alert_groups))
            .where(
                Incident.id == entity_id,
                Incident.organization_id == self.organization_id,
            )
        )

    def incident_history(self, entity_id: uuid.UUID) -> list[IncidentHistory]:
        return list(
            self.session.scalars(
                select(IncidentHistory)
                .where(
                    IncidentHistory.incident_id == entity_id,
                    IncidentHistory.organization_id == self.organization_id,
                )
                .order_by(IncidentHistory.created_at)
            )
        )

    def incident_enrichments(self, entity_id: uuid.UUID) -> list[IncidentEnrichment]:
        return list(
            self.session.scalars(
                select(IncidentEnrichment)
                .where(
                    IncidentEnrichment.incident_id == entity_id,
                    IncidentEnrichment.organization_id == self.organization_id,
                )
                .order_by(IncidentEnrichment.enrichment_type)
            )
        )

    def get_investigation(self, entity_id: uuid.UUID) -> Investigation | None:
        return self.session.scalar(
            select(Investigation).where(
                Investigation.id == entity_id,
                Investigation.organization_id == self.organization_id,
            )
        )

    def get_endpoint_by_agent(self, agent_id: str) -> Endpoint | None:
        return self.session.scalar(
            select(Endpoint).where(
                Endpoint.agent_id == agent_id,
                Endpoint.organization_id == self.organization_id,
            )
        )

    def get_event_by_external_id(self, source: str, external_id: str) -> SecurityEvent | None:
        return self.session.scalar(
            select(SecurityEvent).where(
                SecurityEvent.source == source,
                SecurityEvent.external_id == external_id,
                SecurityEvent.organization_id == self.organization_id,
            )
        )

    def get_alert_by_external_id(self, source: str, external_id: str) -> Alert | None:
        return self.session.scalar(
            select(Alert).where(
                Alert.source == source,
                Alert.external_id == external_id,
                Alert.organization_id == self.organization_id,
            )
        )
