from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.credentials import CredentialStore
from app.core.network import validate_outbound_url
from app.core.security import safe_error
from app.integrations.wazuh.client import WazuhClient
from app.models import IntegrationAccount, IntegrationCheckpoint


class IntegrationService:
    def __init__(self, session: Session, credential_store: CredentialStore) -> None:
        self.session = session
        self.credential_store = credential_store

    def client(self, account: IntegrationAccount) -> WazuhClient:
        credentials = self.credential_store.get(account.credential_reference)
        base_url = validate_outbound_url(account.base_url)
        if credentials.get("indexer_url"):
            credentials = dict(credentials)
            credentials["indexer_url"] = validate_outbound_url(str(credentials["indexer_url"]))
        return WazuhClient(base_url, credentials)

    def checkpoint(self, account: IntegrationAccount, stream: str) -> IntegrationCheckpoint:
        checkpoint = self.session.scalar(
            select(IntegrationCheckpoint).where(
                IntegrationCheckpoint.organization_id == account.organization_id,
                IntegrationCheckpoint.integration_account_id == account.id,
                IntegrationCheckpoint.stream == stream,
            )
        )
        if checkpoint is None:
            checkpoint = IntegrationCheckpoint(
                organization_id=account.organization_id,
                integration_account_id=account.id,
                stream=stream,
            )
            self.session.add(checkpoint)
            self.session.flush()
        return checkpoint

    def success(self, account: IntegrationAccount) -> None:
        account.status = "healthy"
        account.last_success_at = datetime.now(UTC)
        account.last_error = None
        self.session.commit()

    def failure(self, account: IntegrationAccount, exc: Exception) -> None:
        account.status = "error"
        account.last_error_at = datetime.now(UTC)
        account.last_error = safe_error(exc)
        self.session.commit()
