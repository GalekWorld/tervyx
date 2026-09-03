"""Deterministic endpoint-agent enrolment and heartbeat protocol."""

import hashlib
import hmac
import secrets
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import set_tenant_context
from app.models import AuditLog, Endpoint


class EndpointAgentError(ValueError):
    pass


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _certificate_serial(serial: str | None) -> str | None:
    if serial is None:
        return None
    normalized = "".join(serial.split()).upper()
    if (
        not normalized
        or len(normalized) > 255
        or any(char not in "0123456789ABCDEF" for char in normalized)
    ):
        raise EndpointAgentError("Certificate serial is invalid")
    return normalized


def _certificate_expiry(expires_at: datetime | None) -> datetime | None:
    if expires_at is None:
        return None
    if expires_at.tzinfo is None or expires_at <= datetime.now(UTC):
        raise EndpointAgentError("Certificate expiry must be in the future and include a timezone")
    return expires_at


class EndpointAgentService:
    def __init__(self, db: Session):
        self.db = db

    def enroll(
        self,
        organization_id: uuid.UUID,
        endpoint_id: uuid.UUID,
        actor_id: uuid.UUID,
        certificate_serial: str | None = None,
        certificate_expires_at: datetime | None = None,
    ) -> tuple[Endpoint, str]:
        set_tenant_context(self.db, organization_id)
        endpoint = self.db.scalar(
            select(Endpoint)
            .where(
                Endpoint.id == endpoint_id,
                Endpoint.organization_id == organization_id,
            )
            .with_for_update()
        )
        if endpoint is None:
            raise EndpointAgentError("Endpoint not found")
        token = secrets.token_urlsafe(32)
        endpoint.enrollment_token_hash = _hash(token)
        endpoint.enrolled_at = datetime.now(UTC)
        endpoint.revoked_at = None
        endpoint.certificate_serial = _certificate_serial(certificate_serial)
        endpoint.certificate_expires_at = _certificate_expiry(certificate_expires_at)
        endpoint.status = "active"
        self.db.add(
            AuditLog(
                organization_id=organization_id,
                actor_type="user",
                actor_id=str(actor_id),
                action="endpoint.enrolled",
                resource_type="endpoint",
                resource_id=str(endpoint.id),
                details={"identity_key": endpoint.identity_key},
            )
        )
        self.db.flush()
        return endpoint, token

    def heartbeat(
        self,
        organization_id: uuid.UUID,
        identity_key: str,
        token: str,
        health: dict,
        agent_version: str | None,
        certificate_serial: str | None,
    ) -> Endpoint:
        set_tenant_context(self.db, organization_id)
        endpoint = self.db.scalar(
            select(Endpoint)
            .where(
                Endpoint.identity_key == identity_key,
                Endpoint.organization_id == organization_id,
            )
            .with_for_update()
        )
        if (
            endpoint is None
            or endpoint.revoked_at is not None
            or not endpoint.enrollment_token_hash
        ):
            raise EndpointAgentError("Endpoint credentials rejected")
        if not hmac.compare_digest(endpoint.enrollment_token_hash, _hash(token)):
            raise EndpointAgentError("Endpoint credentials rejected")
        if (
            endpoint.certificate_serial
            and _certificate_serial(certificate_serial) != endpoint.certificate_serial
        ):
            raise EndpointAgentError("Certificate identity rejected")
        if endpoint.certificate_expires_at and endpoint.certificate_expires_at <= datetime.now(UTC):
            raise EndpointAgentError("Endpoint certificate expired")
        endpoint.last_seen = datetime.now(UTC)
        endpoint.last_health = health
        endpoint.agent_version = agent_version
        endpoint.status = "active"
        self.db.flush()
        return endpoint

    def revoke(
        self, organization_id: uuid.UUID, endpoint_id: uuid.UUID, actor_id: uuid.UUID, reason: str
    ) -> None:
        set_tenant_context(self.db, organization_id)
        endpoint = self.db.scalar(
            select(Endpoint)
            .where(Endpoint.id == endpoint_id, Endpoint.organization_id == organization_id)
            .with_for_update()
        )
        if endpoint is None:
            raise EndpointAgentError("Endpoint not found")
        endpoint.revoked_at = datetime.now(UTC)
        endpoint.enrollment_token_hash = None
        endpoint.status = "revoked"
        self.db.add(
            AuditLog(
                organization_id=organization_id,
                actor_type="user",
                actor_id=str(actor_id),
                action="endpoint.revoked",
                resource_type="endpoint",
                resource_id=str(endpoint.id),
                details={"reason": reason[:500]},
            )
        )
        self.db.flush()
