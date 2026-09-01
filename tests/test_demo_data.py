from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Alert, Endpoint, Incident, Investigation, Organization, SecurityEvent
from app.services.demo_data import DEMO_ORGANIZATION_ID, seed_demo_data


def test_demo_seed_is_complete_and_idempotent(session: Session) -> None:
    organization = seed_demo_data(session)
    seed_demo_data(session)

    assert organization.id == DEMO_ORGANIZATION_ID
    assert (
        session.scalar(
            select(func.count())
            .select_from(Organization)
            .where(Organization.id == DEMO_ORGANIZATION_ID)
        )
        == 1
    )
    assert (
        session.scalar(
            select(func.count())
            .select_from(Endpoint)
            .where(Endpoint.organization_id == DEMO_ORGANIZATION_ID)
        )
        == 5
    )
    assert (
        session.scalar(
            select(func.count())
            .select_from(SecurityEvent)
            .where(SecurityEvent.organization_id == DEMO_ORGANIZATION_ID)
        )
        == 6
    )
    assert (
        session.scalar(
            select(func.count())
            .select_from(Alert)
            .where(Alert.organization_id == DEMO_ORGANIZATION_ID)
        )
        == 3
    )
    assert (
        session.scalar(
            select(func.count())
            .select_from(Incident)
            .where(Incident.organization_id == DEMO_ORGANIZATION_ID)
        )
        == 1
    )
    assert (
        session.scalar(
            select(func.count())
            .select_from(Investigation)
            .where(Investigation.organization_id == DEMO_ORGANIZATION_ID)
        )
        == 3
    )
