import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from redis import Redis
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.auth import ROLES, Principal, decode_token, effective_capabilities
from app.core.config import get_settings
from app.core.database import get_db, set_tenant_context
from app.models import AuthSession, PrivilegedSession, User, UserCapability
from app.services.quotas import QuotaService, TenantQuotaUnavailable

DbSession = Annotated[Session, Depends(get_db)]
bearer = HTTPBearer(auto_error=False)


def get_principal(
    request: Request,
    db: DbSession,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> Principal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = decode_token(credentials.credentials)
    try:
        session_id = uuid.UUID(payload["sid"]) if payload.get("sid") else None
        privileged_session_id = uuid.UUID(payload["psid"]) if payload.get("psid") else None
        unverified_principal = Principal(
            user_id=uuid.UUID(payload["sub"]),
            organization_id=uuid.UUID(payload["org"]),
            role=payload["role"],
            session_id=session_id,
            privileged_session_id=privileged_session_id,
        )
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=401, detail="Invalid token claims") from exc
    if unverified_principal.role not in ROLES:
        raise HTTPException(status_code=403, detail="Unknown role")
    set_tenant_context(db, unverified_principal.organization_id)
    request.state.tenant_id = str(unverified_principal.organization_id)
    request.state.actor_id = str(unverified_principal.user_id)
    user = db.scalar(
        select(User).where(
            User.id == unverified_principal.user_id,
            User.organization_id == unverified_principal.organization_id,
            User.is_active.is_(True),
        )
    )
    if user is None or user.role != unverified_principal.role:
        raise HTTPException(status_code=401, detail="User is inactive or token is stale")
    auth_session = None
    if unverified_principal.session_id is not None:
        auth_session = db.scalar(
            select(AuthSession).where(
                AuthSession.id == unverified_principal.session_id,
                AuthSession.organization_id == unverified_principal.organization_id,
                AuthSession.user_id == unverified_principal.user_id,
                AuthSession.revoked_at.is_(None),
                AuthSession.expires_at > datetime.now(UTC),
            )
        )
        if auth_session is None:
            raise HTTPException(status_code=401, detail="Session is expired or revoked")
    elif get_settings().app_env != "test":
        raise HTTPException(status_code=401, detail="Session-bound token required")
    mfa_verified = bool(auth_session and auth_session.mfa_verified)
    if user.role == "admin" and get_settings().app_env == "production" and not mfa_verified:
        raise HTTPException(status_code=403, detail="Administrator MFA is required")
    overrides = list(
        db.execute(
            select(UserCapability.capability, UserCapability.effect).where(
                UserCapability.organization_id == user.organization_id,
                UserCapability.user_id == user.id,
            )
        ).tuples()
    )
    privileged_capabilities: frozenset[str] = frozenset()
    if unverified_principal.privileged_session_id is not None:
        if auth_session is None:
            raise HTTPException(status_code=401, detail="Privileged token requires a base session")
        privileged = db.scalar(
            select(PrivilegedSession).where(
                PrivilegedSession.id == unverified_principal.privileged_session_id,
                PrivilegedSession.organization_id == user.organization_id,
                PrivilegedSession.user_id == user.id,
                PrivilegedSession.base_session_id == auth_session.id,
                PrivilegedSession.status == "active",
                PrivilegedSession.expires_at > datetime.now(UTC),
            )
        )
        if privileged is None:
            raise HTTPException(status_code=401, detail="Privileged session is expired or revoked")
        privileged_capabilities = frozenset(privileged.capabilities)
    if get_settings().app_env != "test":
        try:
            redis = Redis.from_url(get_settings().celery_broker_url)
            if not QuotaService(db).allow_api(redis, user.organization_id):
                raise HTTPException(status_code=429, detail="Tenant API quota exceeded")
        except TenantQuotaUnavailable as exc:
            raise HTTPException(
                status_code=503, detail="Tenant API quota service unavailable"
            ) from exc
    return Principal(
        user_id=user.id,
        organization_id=user.organization_id,
        role=user.role,
        capabilities=effective_capabilities(user.role, overrides),
        session_id=auth_session.id if auth_session else None,
        mfa_verified=mfa_verified,
        privileged_session_id=unverified_principal.privileged_session_id,
        privileged_capabilities=privileged_capabilities,
    )


CurrentPrincipal = Annotated[Principal, Depends(get_principal)]


def get_organization_id(principal: CurrentPrincipal) -> uuid.UUID:
    return principal.organization_id


OrganizationId = Annotated[uuid.UUID, Depends(get_organization_id)]


def require_role(minimum: str) -> Callable:
    def dependency(principal: CurrentPrincipal) -> Principal:
        if ROLES[principal.role] < ROLES[minimum]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions"
            )
        return principal

    return dependency


Viewer = Annotated[Principal, Depends(require_role("viewer"))]
Analyst = Annotated[Principal, Depends(require_role("analyst"))]
Admin = Annotated[Principal, Depends(require_role("admin"))]


def require_capability(capability: str) -> Callable:
    def dependency(principal: CurrentPrincipal) -> Principal:
        if capability not in principal.capabilities:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Missing required capability"
            )
        return principal

    return dependency


SecurityReader = Annotated[Principal, Depends(require_capability("security.read"))]
EventIngester = Annotated[Principal, Depends(require_capability("events.ingest"))]
IntegrationReader = Annotated[Principal, Depends(require_capability("integrations.read"))]
IntegrationManager = Annotated[Principal, Depends(require_capability("integrations.manage"))]
IntegrationExecutor = Annotated[Principal, Depends(require_capability("integrations.execute"))]
DeadLetterReader = Annotated[Principal, Depends(require_capability("dead_letters.read"))]
DeadLetterReprocessor = Annotated[Principal, Depends(require_capability("dead_letters.reprocess"))]
DeadLetterDiscarer = Annotated[Principal, Depends(require_capability("dead_letters.discard"))]
IdentityManager = Annotated[Principal, Depends(require_capability("identity.manage"))]
SessionRevoker = Annotated[Principal, Depends(require_capability("sessions.revoke"))]
SecretRotator = Annotated[Principal, Depends(require_capability("secrets.rotate"))]
AuditReader = Annotated[Principal, Depends(require_capability("audit.read"))]


def require_privileged_capability(capability: str) -> Callable:
    def dependency(principal: CurrentPrincipal) -> Principal:
        if (
            principal.privileged_session_id is None
            or capability not in principal.privileged_capabilities
        ):
            raise HTTPException(
                status_code=403, detail="Active JIT Platform Admin session required"
            )
        return principal

    return dependency
