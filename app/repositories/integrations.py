import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import DeadLetterEvent, IntegrationAccount, IntegrationCheckpoint


class IntegrationRepository:
    def __init__(self, session: Session, organization_id: uuid.UUID) -> None:
        self.session = session
        self.organization_id = organization_id

    def list_all(self) -> list[IntegrationAccount]:
        return list(
            self.session.scalars(
                select(IntegrationAccount)
                .where(IntegrationAccount.organization_id == self.organization_id)
                .order_by(IntegrationAccount.name)
            )
        )

    def get(self, entity_id: uuid.UUID) -> IntegrationAccount | None:
        return self.session.scalar(
            select(IntegrationAccount).where(
                IntegrationAccount.id == entity_id,
                IntegrationAccount.organization_id == self.organization_id,
            )
        )

    def checkpoints(self, account_id: uuid.UUID) -> list[IntegrationCheckpoint]:
        return list(
            self.session.scalars(
                select(IntegrationCheckpoint).where(
                    IntegrationCheckpoint.integration_account_id == account_id,
                    IntegrationCheckpoint.organization_id == self.organization_id,
                )
            )
        )

    def dead_letters(self, page: int, page_size: int, status: str | None = None):
        from sqlalchemy import func

        statement = select(DeadLetterEvent).where(
            DeadLetterEvent.organization_id == self.organization_id
        )
        if status:
            statement = statement.where(DeadLetterEvent.status == status)
        total = self.session.scalar(select(func.count()).select_from(statement.subquery())) or 0
        items = list(
            self.session.scalars(
                statement.order_by(DeadLetterEvent.created_at.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        )
        return items, total

    def dead_letter(self, entity_id: uuid.UUID) -> DeadLetterEvent | None:
        return self.session.scalar(
            select(DeadLetterEvent).where(
                DeadLetterEvent.id == entity_id,
                DeadLetterEvent.organization_id == self.organization_id,
            )
        )
