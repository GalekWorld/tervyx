import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Header, HTTPException, Query, Response, status
from sqlalchemy import select

from app.api.dependencies import (
    Admin,
    Analyst,
    AuditReader,
    CurrentPrincipal,
    DbSession,
    DeadLetterDiscarer,
    DeadLetterReader,
    DeadLetterReprocessor,
    EventIngester,
    IdentityManager,
    IntegrationExecutor,
    IntegrationManager,
    IntegrationReader,
    OrganizationId,
    SecretRotator,
    SecurityReader,
    SessionRevoker,
)
from app.core.auth import (
    ALL_CAPABILITIES,
    create_access_token,
    create_refresh_secret,
    create_worker_token,
    get_signing_key_ring,
    hash_refresh_token,
    refresh_token_organization,
    verify_password,
)
from app.core.config import get_settings
from app.core.credentials import CredentialStoreError, get_credential_store
from app.core.database import set_tenant_context
from app.core.network import UnsafeURLError, validate_outbound_url
from app.detection.rules import DEFAULT_RULES
from app.integrations.base import AdapterError
from app.integrations.registry import AdapterRegistry
from app.integrations.wazuh import WazuhAdapter
from app.models import (
    AuditLog,
    AuthSession,
    DetectionRuleConfiguration,
    DetectionRuleMetric,
    IdentityProvider,
    IntegrationAccount,
    Investigation,
    Organization,
    RefreshToken,
    User,
    UserCapability,
)
from app.repositories import IntegrationRepository, SecurityRepository
from app.schemas import (
    AlertGroupAssignmentUpdate,
    AlertGroupFeedbackUpdate,
    AlertGroupHistoryRead,
    AlertGroupRead,
    AlertGroupStatusUpdate,
    AlertRead,
    DetectionRuleConfigurationRead,
    DetectionRuleConfigurationUpdate,
    DetectionRuleMetricRead,
    EndpointEnrollRequest,
    EndpointEnrollResponse,
    EndpointHeartbeatRequest,
    EndpointRead,
    EventIngestRequest,
    IncidentAssignmentUpdate,
    IncidentEnrichmentRead,
    IncidentHistoryRead,
    IncidentRead,
    IncidentReopenRequest,
    IncidentResolutionUpdate,
    IncidentStatusUpdate,
    IngestResult,
    InvestigationRead,
    InvestigationStatusUpdate,
    SecurityEventRead,
    SecuritySignalRead,
)
from app.schemas.auth import LoginRequest, RefreshRequest, RevokeRequest, TokenResponse
from app.schemas.dlq import DeadLetterRead
from app.schemas.identity import (
    CapabilityGrantRead,
    CapabilityGrantRequest,
    IdentityProviderCreate,
    IdentityProviderRead,
    OIDCAuthorizeRequest,
    OIDCAuthorizeResponse,
    OIDCCallbackRequest,
    PrivilegedAccessApproval,
    PrivilegedAccessRead,
    PrivilegedAccessRequestCreate,
    PrivilegedAccessRevoke,
    PrivilegedTokenResponse,
    SecretRotationRequest,
    SecretRotationResponse,
    SessionRead,
)
from app.schemas.integrations import (
    IntegrationCreate,
    IntegrationRead,
    IntegrationStatus,
    JobAccepted,
)
from app.services.alert_group_lifecycle import (
    AlertGroupLifecycleService,
    InvalidAlertGroupTransition,
)
from app.services.audit_ledger import AuditLedgerService
from app.services.detection import DetectionConfigurationService
from app.services.endpoint_agent import EndpointAgentError, EndpointAgentService
from app.services.identity import IdentityError, IdentityService
from app.services.incident_lifecycle import IncidentLifecycleService, InvalidIncidentTransition
from app.services.ingestion import IngestionService
from app.services.investigation import InvalidInvestigationTransition, InvestigationService
from app.services.pam import PrivilegedAccessError, PrivilegedAccessService
from app.workers.tasks import (
    enqueue_task,
    reprocess_dead_letter,
    sync_wazuh_agents,
    sync_wazuh_alerts,
    test_wazuh_connection,
)

router = APIRouter()
AgentOrganizationHeader = Annotated[uuid.UUID, Header(..., alias="X-Agent-Organization-Id")]


def _token_response(
    db: DbSession, user: User, auth_session: AuthSession | None = None
) -> TokenResponse:
    settings = get_settings()
    now = datetime.now(UTC)
    if auth_session is None:
        auth_session = AuthSession(
            organization_id=user.organization_id,
            user_id=user.id,
            auth_method="password",
            mfa_verified=False,
            expires_at=now + timedelta(hours=settings.session_ttl_hours),
            last_seen_at=now,
        )
        db.add(auth_session)
        db.flush()
    refresh_secret, token_hash = create_refresh_secret(user.organization_id)
    session_expires_at = auth_session.expires_at
    if session_expires_at.tzinfo is None:
        session_expires_at = session_expires_at.replace(tzinfo=UTC)
    db.add(
        RefreshToken(
            organization_id=user.organization_id,
            user_id=user.id,
            session_id=auth_session.id,
            token_hash=token_hash,
            expires_at=min(
                session_expires_at, now + timedelta(days=settings.refresh_token_ttl_days)
            ),
        )
    )
    return TokenResponse(
        access_token=create_access_token(
            user.id,
            user.organization_id,
            user.role,
            session_id=auth_session.id,
            mfa_verified=auth_session.mfa_verified,
        ),
        refresh_token=refresh_secret,
        expires_in=settings.access_token_ttl_minutes * 60,
    )


@router.post("/auth/token", response_model=TokenResponse)
def login(request: LoginRequest, db: DbSession):
    organization = db.scalar(
        select(Organization).where(Organization.slug == request.organization_slug)
    )
    if organization is None:
        raise HTTPException(401, "Invalid credentials")
    set_tenant_context(db, organization.id)
    user = db.scalar(
        select(User).where(
            User.organization_id == organization.id,
            User.email == request.email,
            User.is_active.is_(True),
        )
    )
    if (
        user is None
        or not user.password_hash
        or not verify_password(request.password, user.password_hash)
    ):
        raise HTTPException(401, "Invalid credentials")
    if user.role == "admin" and get_settings().app_env == "production":
        raise HTTPException(403, "Administrators must authenticate through MFA-protected SSO")
    db.add(
        AuditLog(
            organization_id=organization.id,
            actor_type="user",
            actor_id=str(user.id),
            action="auth.login_succeeded",
            resource_type="user",
            resource_id=str(user.id),
            details={},
        )
    )
    response = _token_response(db, user)
    db.commit()
    return response


@router.get("/auth/jwks")
def jwks():
    return get_signing_key_ring().jwks()


@router.post("/auth/refresh", response_model=TokenResponse)
def refresh_access_token(request: RefreshRequest, db: DbSession):
    organization_id = refresh_token_organization(request.refresh_token)
    set_tenant_context(db, organization_id)
    now = datetime.now(UTC)
    current = db.scalar(
        select(RefreshToken).where(
            RefreshToken.organization_id == organization_id,
            RefreshToken.token_hash == hash_refresh_token(request.refresh_token),
            RefreshToken.revoked_at.is_(None),
            RefreshToken.expires_at > now,
        )
    )
    if current is None:
        raise HTTPException(401, "Invalid or expired refresh token")
    auth_session = db.scalar(
        select(AuthSession).where(
            AuthSession.id == current.session_id,
            AuthSession.organization_id == organization_id,
            AuthSession.revoked_at.is_(None),
            AuthSession.expires_at > now,
        )
    )
    if auth_session is None:
        raise HTTPException(401, "Session is expired or revoked")
    user = db.scalar(
        select(User).where(
            User.id == current.user_id,
            User.organization_id == organization_id,
            User.is_active.is_(True),
        )
    )
    if user is None:
        raise HTTPException(401, "User is inactive")
    current.revoked_at = now
    response = _token_response(db, user, auth_session)
    db.flush()
    replacement = db.scalar(
        select(RefreshToken).where(
            RefreshToken.token_hash == hash_refresh_token(response.refresh_token)
        )
    )
    current.replaced_by_id = replacement.id if replacement else None
    db.add(
        AuditLog(
            organization_id=organization_id,
            actor_type="user",
            actor_id=str(user.id),
            action="auth.refresh_rotated",
            resource_type="user",
            resource_id=str(user.id),
            details={},
        )
    )
    db.commit()
    return response


@router.post("/auth/revoke", status_code=204)
def revoke_refresh_token(request: RevokeRequest, db: DbSession):
    organization_id = refresh_token_organization(request.refresh_token)
    set_tenant_context(db, organization_id)
    current = db.scalar(
        select(RefreshToken).where(
            RefreshToken.organization_id == organization_id,
            RefreshToken.token_hash == hash_refresh_token(request.refresh_token),
        )
    )
    if current is not None and current.revoked_at is None:
        current.revoked_at = datetime.now(UTC)
        auth_session = (
            db.scalar(
                select(AuthSession).where(
                    AuthSession.id == current.session_id,
                    AuthSession.organization_id == organization_id,
                )
            )
            if current.session_id
            else None
        )
        if auth_session is not None:
            auth_session.revoked_at = current.revoked_at
            auth_session.revocation_reason = "refresh token revoked"
        db.add(
            AuditLog(
                organization_id=organization_id,
                actor_type="user",
                actor_id=str(current.user_id),
                action="auth.refresh_revoked",
                resource_type="refresh_token",
                resource_id=str(current.id),
                details={},
            )
        )
        db.commit()
    return Response(status_code=204)


@router.post("/auth/oidc/authorize", response_model=OIDCAuthorizeResponse)
def oidc_authorize(request: OIDCAuthorizeRequest, db: DbSession):
    organization = db.scalar(
        select(Organization).where(Organization.slug == request.organization_slug)
    )
    if organization is None:
        raise HTTPException(404, "OIDC provider not found")
    set_tenant_context(db, organization.id)
    provider = db.scalar(
        select(IdentityProvider).where(
            IdentityProvider.organization_id == organization.id,
            IdentityProvider.name == request.provider_name,
            IdentityProvider.enabled.is_(True),
        )
    )
    if provider is None:
        raise HTTPException(404, "OIDC provider not found")
    try:
        url, expires_in = IdentityService(db, get_credential_store()).begin(
            provider, request.redirect_uri
        )
    except (IdentityError, CredentialStoreError, UnsafeURLError) as exc:
        db.rollback()
        raise HTTPException(400, str(exc)) from exc
    return OIDCAuthorizeResponse(authorization_url=url, expires_in=expires_in)


@router.post("/auth/oidc/callback", response_model=TokenResponse)
def oidc_callback(request: OIDCCallbackRequest, db: DbSession):
    try:
        user, auth_session = IdentityService(db, get_credential_store()).callback(
            request.state, request.code, request.redirect_uri
        )
        response = _token_response(db, user, auth_session)
        db.commit()
        return response
    except (IdentityError, CredentialStoreError, UnsafeURLError) as exc:
        db.rollback()
        raise HTTPException(401, str(exc)) from exc


@router.post("/auth/logout", status_code=204)
def logout(db: DbSession, principal: CurrentPrincipal):
    if principal.session_id is None:
        raise HTTPException(400, "Session-bound token required")
    auth_session = db.scalar(
        select(AuthSession).where(
            AuthSession.id == principal.session_id,
            AuthSession.organization_id == principal.organization_id,
            AuthSession.user_id == principal.user_id,
        )
    )
    if auth_session is not None and auth_session.revoked_at is None:
        IdentityService(db, get_credential_store()).revoke_session(
            auth_session, actor_id=principal.user_id, reason="user logout"
        )
    return Response(status_code=204)


@router.post("/auth/logout-all", status_code=204)
def logout_all(db: DbSession, principal: CurrentPrincipal):
    IdentityService(db, get_credential_store()).revoke_user_sessions(
        principal.organization_id,
        principal.user_id,
        actor_id=principal.user_id,
        reason="user global logout",
    )
    return Response(status_code=204)


@router.post("/platform-admin/requests", response_model=PrivilegedAccessRead, status_code=201)
def request_platform_admin_access(
    request: PrivilegedAccessRequestCreate, db: DbSession, principal: CurrentPrincipal
):
    service = PrivilegedAccessService(db, principal.organization_id)
    try:
        item = service.request(
            principal,
            purpose=request.purpose,
            capabilities=request.capabilities,
            duration_minutes=request.duration_minutes,
            break_glass=request.break_glass,
        )
        db.commit()
        db.refresh(item)
        return item
    except PrivilegedAccessError as exc:
        db.rollback()
        raise HTTPException(403, str(exc)) from exc


@router.post("/platform-admin/requests/{request_id}/approve", response_model=PrivilegedAccessRead)
def approve_platform_admin_access(
    request_id: uuid.UUID,
    _request: PrivilegedAccessApproval,
    db: DbSession,
    principal: CurrentPrincipal,
):
    service = PrivilegedAccessService(db, principal.organization_id)
    try:
        item = service.approve(principal, request_id)
        db.commit()
        db.refresh(item)
        return item
    except PrivilegedAccessError as exc:
        db.rollback()
        raise HTTPException(403, str(exc)) from exc


@router.post(
    "/platform-admin/requests/{request_id}/activate", response_model=PrivilegedTokenResponse
)
def activate_platform_admin_access(
    request_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal
):
    service = PrivilegedAccessService(db, principal.organization_id)
    try:
        activated = service.activate(principal, request_id)
        db.commit()
    except PrivilegedAccessError as exc:
        db.rollback()
        raise HTTPException(403, str(exc)) from exc
    privileged = activated.session
    return PrivilegedTokenResponse(
        access_token=create_access_token(
            principal.user_id,
            principal.organization_id,
            principal.role,
            session_id=principal.session_id,
            mfa_verified=True,
            privileged_session_id=privileged.id,
            privileged_capabilities=activated.capabilities,
            expires_at=privileged.expires_at,
        ),
        privileged_session_id=privileged.id,
        expires_in=max(0, int((privileged.expires_at - datetime.now(UTC)).total_seconds())),
    )


@router.post("/platform-admin/sessions/{privileged_session_id}/revoke", status_code=204)
def revoke_platform_admin_access(
    privileged_session_id: uuid.UUID,
    request: PrivilegedAccessRevoke,
    db: DbSession,
    principal: CurrentPrincipal,
):
    service = PrivilegedAccessService(db, principal.organization_id)
    try:
        service.revoke(principal, privileged_session_id, reason=request.reason)
        db.commit()
    except PrivilegedAccessError as exc:
        db.rollback()
        raise HTTPException(403, str(exc)) from exc
    return Response(status_code=204)


@router.post("/identity-providers", response_model=IdentityProviderRead, status_code=201)
def create_identity_provider(
    request: IdentityProviderCreate,
    db: DbSession,
    organization_id: OrganizationId,
    principal: IdentityManager,
):
    try:
        issuer = validate_outbound_url(request.issuer)
        get_credential_store().get(organization_id, request.client_secret_reference)
    except (UnsafeURLError, CredentialStoreError) as exc:
        raise HTTPException(422, str(exc)) from exc
    if request.provider_type == "entra":
        if not request.provider_tenant_id:
            raise HTTPException(422, "Entra provider tenant ID is required")
        expected = f"https://login.microsoftonline.com/{request.provider_tenant_id}/v2.0"
        if issuer.rstrip("/").lower() != expected.lower():
            raise HTTPException(422, "Entra issuer must match the configured tenant")
    provider = IdentityProvider(
        organization_id=organization_id,
        provider_type=request.provider_type,
        name=request.name,
        issuer=issuer,
        client_id=request.client_id,
        client_secret_reference=request.client_secret_reference,
        scopes=request.scopes,
        allowed_redirect_uris=request.allowed_redirect_uris,
        enforce_mfa=request.enforce_mfa,
        provider_tenant_id=request.provider_tenant_id,
    )
    db.add(provider)
    db.flush()
    db.add(
        AuditLog(
            organization_id=organization_id,
            actor_type="user",
            actor_id=str(principal.user_id),
            action="identity.provider_created",
            resource_type="identity_provider",
            resource_id=str(provider.id),
            details={"provider_type": provider.provider_type, "enforce_mfa": provider.enforce_mfa},
        )
    )
    db.commit()
    db.refresh(provider)
    return provider


@router.get("/identity-providers", response_model=list[IdentityProviderRead])
def list_identity_providers(
    db: DbSession, organization_id: OrganizationId, _principal: IdentityManager
):
    return list(
        db.scalars(
            select(IdentityProvider).where(IdentityProvider.organization_id == organization_id)
        )
    )


@router.get("/auth/sessions", response_model=list[SessionRead])
def list_sessions(db: DbSession, principal: CurrentPrincipal):
    return list(
        db.scalars(
            select(AuthSession).where(
                AuthSession.organization_id == principal.organization_id,
                AuthSession.user_id == principal.user_id,
            )
        )
    )


@router.post("/users/{user_id}/sessions/revoke", status_code=204)
def revoke_user_sessions(
    user_id: uuid.UUID,
    db: DbSession,
    organization_id: OrganizationId,
    principal: SessionRevoker,
):
    user = db.scalar(
        select(User).where(User.id == user_id, User.organization_id == organization_id)
    )
    if user is None:
        raise HTTPException(404, "User not found")
    IdentityService(db, get_credential_store()).revoke_user_sessions(
        organization_id,
        user_id,
        actor_id=principal.user_id,
        reason="administrator emergency revocation",
    )
    return Response(status_code=204)


@router.get("/users/{user_id}/capabilities", response_model=list[CapabilityGrantRead])
def list_user_capabilities(
    user_id: uuid.UUID,
    db: DbSession,
    organization_id: OrganizationId,
    _principal: IdentityManager,
):
    return list(
        db.scalars(
            select(UserCapability).where(
                UserCapability.organization_id == organization_id,
                UserCapability.user_id == user_id,
            )
        )
    )


@router.put("/users/{user_id}/capabilities/{capability}", response_model=CapabilityGrantRead)
def set_user_capability(
    user_id: uuid.UUID,
    capability: str,
    request: CapabilityGrantRequest,
    db: DbSession,
    organization_id: OrganizationId,
    principal: IdentityManager,
):
    if capability not in ALL_CAPABILITIES:
        raise HTTPException(422, "Unknown capability")
    user = db.scalar(
        select(User).where(User.id == user_id, User.organization_id == organization_id)
    )
    if user is None:
        raise HTTPException(404, "User not found")
    grant = db.scalar(
        select(UserCapability).where(
            UserCapability.organization_id == organization_id,
            UserCapability.user_id == user_id,
            UserCapability.capability == capability,
        )
    )
    if grant is None:
        grant = UserCapability(
            organization_id=organization_id,
            user_id=user_id,
            capability=capability,
            effect=request.effect,
        )
        db.add(grant)
    else:
        grant.effect = request.effect
    db.add(
        AuditLog(
            organization_id=organization_id,
            actor_type="user",
            actor_id=str(principal.user_id),
            action="identity.capability_changed",
            resource_type="user",
            resource_id=str(user_id),
            details={"capability": capability, "effect": request.effect},
        )
    )
    db.commit()
    db.refresh(grant)
    return grant


def _repo(db: DbSession, organization_id: OrganizationId) -> SecurityRepository:
    return SecurityRepository(db, organization_id)


@router.post("/events", response_model=IngestResult, status_code=status.HTTP_201_CREATED)
def ingest_event(
    request: EventIngestRequest,
    db: DbSession,
    organization_id: OrganizationId,
    _principal: EventIngester,
) -> IngestResult:
    service = IngestionService(db, AdapterRegistry([WazuhAdapter()]))
    try:
        return service.ingest(organization_id, request.source, request.payload)
    except (AdapterError, ValueError) as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/endpoints", response_model=list[EndpointRead])
def list_endpoints(
    response: Response,
    db: DbSession,
    organization_id: OrganizationId,
    _principal: SecurityReader,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    status_filter: str | None = Query(None, alias="status"),
):
    items, total = _repo(db, organization_id).page_endpoints(page, page_size, status=status_filter)
    response.headers["X-Total-Count"] = str(total)
    return items


@router.get("/events", response_model=list[SecurityEventRead])
def list_events(
    response: Response,
    db: DbSession,
    organization_id: OrganizationId,
    _principal: SecurityReader,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    severity: int | None = Query(None, ge=0, le=10),
    source: str | None = None,
    endpoint: uuid.UUID | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
):
    items, total = _repo(db, organization_id).page_events(
        page,
        page_size,
        severity=severity,
        source=source,
        endpoint_id=endpoint,
        date_from=date_from,
        date_to=date_to,
    )
    response.headers["X-Total-Count"] = str(total)
    return items


@router.get("/endpoints/{entity_id}", response_model=EndpointRead)
def get_endpoint(
    entity_id: uuid.UUID,
    db: DbSession,
    organization_id: OrganizationId,
    _principal: SecurityReader,
):
    entity = _repo(db, organization_id).get_endpoint(entity_id)
    if entity is None:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return entity


@router.post("/endpoints/enroll", response_model=EndpointEnrollResponse)
def enroll_endpoint(
    request: EndpointEnrollRequest, db: DbSession, organization_id: OrganizationId, principal: Admin
):
    try:
        endpoint, token = EndpointAgentService(db).enroll(
            organization_id,
            request.endpoint_id,
            principal.user_id,
            request.certificate_serial,
            request.certificate_expires_at,
        )
        db.commit()
        return EndpointEnrollResponse(
            endpoint_id=endpoint.id,
            organization_id=organization_id,
            identity_key=endpoint.identity_key,
            enrollment_token=token,
        )
    except EndpointAgentError as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/endpoints/agent/{identity_key}/heartbeat", response_model=EndpointRead)
def endpoint_heartbeat(
    identity_key: str,
    request: EndpointHeartbeatRequest,
    db: DbSession,
    agent_organization_id: AgentOrganizationHeader,
    agent_token: str = Header(..., alias="X-Agent-Token"),
    certificate_serial: str | None = Header(None, alias="X-Agent-Certificate-Serial"),
):
    try:
        endpoint = EndpointAgentService(db).heartbeat(
            agent_organization_id,
            identity_key,
            agent_token,
            request.health,
            request.agent_version,
            certificate_serial or request.certificate_serial,
        )
        db.commit()
        return endpoint
    except EndpointAgentError as exc:
        db.rollback()
        raise HTTPException(status_code=401, detail="Endpoint credentials rejected") from exc


@router.post("/endpoints/{entity_id}/revoke", status_code=status.HTTP_204_NO_CONTENT)
def revoke_endpoint(
    entity_id: uuid.UUID, db: DbSession, organization_id: OrganizationId, principal: Admin
):
    try:
        EndpointAgentService(db).revoke(
            organization_id, entity_id, principal.user_id, "administrative revocation"
        )
        db.commit()
    except EndpointAgentError as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/alerts", response_model=list[AlertRead])
def list_alerts(
    response: Response,
    db: DbSession,
    organization_id: OrganizationId,
    _principal: SecurityReader,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    severity: int | None = Query(None, ge=0, le=10),
    status_filter: str | None = Query(None, alias="status"),
    source: str | None = None,
    endpoint: uuid.UUID | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
):
    items, total = _repo(db, organization_id).page_alerts(
        page,
        page_size,
        severity=severity,
        status=status_filter,
        source=source,
        endpoint_id=endpoint,
        date_from=date_from,
        date_to=date_to,
    )
    response.headers["X-Total-Count"] = str(total)
    return items


@router.get("/alerts/{entity_id}", response_model=AlertRead)
def get_alert(
    entity_id: uuid.UUID,
    db: DbSession,
    organization_id: OrganizationId,
    _principal: SecurityReader,
):
    entity = _repo(db, organization_id).get_alert(entity_id)
    if entity is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return entity


@router.get("/alert-groups", response_model=list[AlertGroupRead])
def list_alert_groups(db: DbSession, organization_id: OrganizationId, _principal: SecurityReader):
    return _repo(db, organization_id).list_alert_groups()


@router.get("/alert-groups/{entity_id}", response_model=AlertGroupRead)
def get_alert_group(
    entity_id: uuid.UUID,
    db: DbSession,
    organization_id: OrganizationId,
    _principal: SecurityReader,
):
    entity = _repo(db, organization_id).get_alert_group(entity_id)
    if entity is None:
        raise HTTPException(status_code=404, detail="Alert group not found")
    return entity


@router.patch("/alert-groups/{entity_id}/status", response_model=AlertGroupRead)
def update_alert_group_status(
    entity_id: uuid.UUID,
    request: AlertGroupStatusUpdate,
    db: DbSession,
    organization_id: OrganizationId,
    principal: Analyst,
):
    group = _repo(db, organization_id).get_alert_group(entity_id)
    if group is None:
        raise HTTPException(404, "Alert group not found")
    try:
        AlertGroupLifecycleService(db, organization_id).transition(
            group, principal.user_id, request.status, request.resolution_reason
        )
    except InvalidAlertGroupTransition as exc:
        raise HTTPException(422, str(exc)) from exc
    db.add(
        AuditLog(
            organization_id=organization_id,
            actor_type="user",
            actor_id=str(principal.user_id),
            action="alert_group.status_changed",
            resource_type="alert_group",
            resource_id=str(group.id),
            details={"status": request.status},
        )
    )
    db.commit()
    db.refresh(group)
    return group


@router.patch("/alert-groups/{entity_id}/assignment", response_model=AlertGroupRead)
def assign_alert_group(
    entity_id: uuid.UUID,
    request: AlertGroupAssignmentUpdate,
    db: DbSession,
    organization_id: OrganizationId,
    principal: Analyst,
):
    group = _repo(db, organization_id).get_alert_group(entity_id)
    if group is None:
        raise HTTPException(404, "Alert group not found")
    if request.assigned_to is not None:
        assignee = db.scalar(
            select(User).where(
                User.id == request.assigned_to,
                User.organization_id == organization_id,
                User.is_active.is_(True),
            )
        )
        if assignee is None:
            raise HTTPException(404, "Assignee not found")
    AlertGroupLifecycleService(db, organization_id).assign(
        group, principal.user_id, request.assigned_to
    )
    db.add(
        AuditLog(
            organization_id=organization_id,
            actor_type="user",
            actor_id=str(principal.user_id),
            action="alert_group.assigned",
            resource_type="alert_group",
            resource_id=str(group.id),
            details={"assigned_to": str(request.assigned_to) if request.assigned_to else None},
        )
    )
    db.commit()
    db.refresh(group)
    return group


@router.post("/alert-groups/{entity_id}/feedback", response_model=AlertGroupRead)
def add_alert_group_feedback(
    entity_id: uuid.UUID,
    request: AlertGroupFeedbackUpdate,
    db: DbSession,
    organization_id: OrganizationId,
    principal: Analyst,
):
    group = _repo(db, organization_id).get_alert_group(entity_id)
    if group is None:
        raise HTTPException(404, "Alert group not found")
    AlertGroupLifecycleService(db, organization_id).feedback(
        group, principal.user_id, request.analyst_feedback
    )
    db.add(
        AuditLog(
            organization_id=organization_id,
            actor_type="user",
            actor_id=str(principal.user_id),
            action="alert_group.feedback_added",
            resource_type="alert_group",
            resource_id=str(group.id),
            details={},
        )
    )
    db.commit()
    db.refresh(group)
    return group


@router.get("/alert-groups/{entity_id}/history", response_model=list[AlertGroupHistoryRead])
def alert_group_history(
    entity_id: uuid.UUID,
    db: DbSession,
    organization_id: OrganizationId,
    _principal: SecurityReader,
):
    if _repo(db, organization_id).get_alert_group(entity_id) is None:
        raise HTTPException(404, "Alert group not found")
    return _repo(db, organization_id).alert_group_history(entity_id)


@router.get("/detection-rules", response_model=list[DetectionRuleConfigurationRead])
def list_detection_rules(
    db: DbSession, organization_id: OrganizationId, _principal: SecurityReader
):
    return list(
        db.scalars(
            select(DetectionRuleConfiguration)
            .where(
                DetectionRuleConfiguration.organization_id == organization_id,
                DetectionRuleConfiguration.active.is_(True),
            )
            .order_by(DetectionRuleConfiguration.rule_id)
        )
    )


@router.put(
    "/detection-rules/{rule_id}", response_model=DetectionRuleConfigurationRead, status_code=201
)
def configure_detection_rule(
    rule_id: str,
    request: DetectionRuleConfigurationUpdate,
    db: DbSession,
    organization_id: OrganizationId,
    principal: Admin,
):
    if rule_id not in {rule.rule_id for rule in DEFAULT_RULES}:
        raise HTTPException(404, "Detection rule not found")
    configuration = DetectionConfigurationService(db, organization_id).configure(
        rule_id,
        enabled=request.enabled,
        suppression_window_seconds=request.suppression_window_seconds,
        configuration=request.configuration,
    )
    db.add(
        AuditLog(
            organization_id=organization_id,
            actor_type="user",
            actor_id=str(principal.user_id),
            action="detection_rule.configured",
            resource_type="detection_rule",
            resource_id=rule_id,
            details={
                "version": configuration.version,
                "enabled": configuration.enabled,
                "suppression_window_seconds": configuration.suppression_window_seconds,
            },
        )
    )
    db.commit()
    db.refresh(configuration)
    return configuration


@router.get("/detection-rules/metrics", response_model=list[DetectionRuleMetricRead])
def list_detection_rule_metrics(
    db: DbSession, organization_id: OrganizationId, _principal: SecurityReader
):
    return list(
        db.scalars(
            select(DetectionRuleMetric)
            .where(DetectionRuleMetric.organization_id == organization_id)
            .order_by(DetectionRuleMetric.rule_id)
        )
    )


@router.get("/security/signals", response_model=list[SecuritySignalRead])
def list_security_signals(
    db: DbSession,
    organization_id: OrganizationId,
    _principal: Admin,
    limit: int = Query(100, ge=1, le=500),
):
    from app.models import SecuritySignal

    return list(
        db.scalars(
            select(SecuritySignal)
            .where(SecuritySignal.organization_id == organization_id)
            .order_by(SecuritySignal.last_seen_at.desc())
            .limit(limit)
        )
    )


@router.get("/audit/ledger/verify")
def verify_audit_ledger(
    db: DbSession, organization_id: OrganizationId, _principal: AuditReader
) -> dict[str, int | bool | str | None]:
    result = AuditLedgerService(db).verify(organization_id)
    return {"valid": result.valid, "entries": result.entries, "error": result.error}


@router.get("/audit/ledger/export")
def export_audit_ledger(
    db: DbSession, organization_id: OrganizationId, _principal: AuditReader
) -> list[dict]:
    return AuditLedgerService(db).export(organization_id)


@router.get("/incidents", response_model=list[IncidentRead])
def list_incidents(db: DbSession, organization_id: OrganizationId, _principal: SecurityReader):
    return _repo(db, organization_id).list_incidents()


@router.get("/incidents/{entity_id}", response_model=IncidentRead)
def get_incident(
    entity_id: uuid.UUID,
    db: DbSession,
    organization_id: OrganizationId,
    _principal: SecurityReader,
):
    entity = _repo(db, organization_id).get_incident(entity_id)
    if entity is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return entity


@router.patch("/incidents/{entity_id}/status", response_model=IncidentRead)
def update_incident_status(
    entity_id: uuid.UUID,
    request: IncidentStatusUpdate,
    db: DbSession,
    organization_id: OrganizationId,
    principal: Analyst,
):
    incident = _repo(db, organization_id).get_incident(entity_id)
    if incident is None:
        raise HTTPException(404, "Incident not found")
    try:
        IncidentLifecycleService(db, organization_id).transition(
            incident, principal.user_id, request.status, request.resolution
        )
    except InvalidIncidentTransition as exc:
        raise HTTPException(422, str(exc)) from exc
    db.add(
        AuditLog(
            organization_id=organization_id,
            actor_type="user",
            actor_id=str(principal.user_id),
            action="incident.status_changed",
            resource_type="incident",
            resource_id=str(incident.id),
            details={"status": request.status},
        )
    )
    db.commit()
    db.refresh(incident)
    return incident


@router.patch("/incidents/{entity_id}/assignment", response_model=IncidentRead)
def assign_incident(
    entity_id: uuid.UUID,
    request: IncidentAssignmentUpdate,
    db: DbSession,
    organization_id: OrganizationId,
    principal: Analyst,
):
    incident = _repo(db, organization_id).get_incident(entity_id)
    if incident is None:
        raise HTTPException(404, "Incident not found")
    if request.assigned_to is not None:
        assignee = db.scalar(
            select(User).where(
                User.id == request.assigned_to,
                User.organization_id == organization_id,
                User.is_active.is_(True),
            )
        )
        if assignee is None:
            raise HTTPException(404, "Assignee not found")
    IncidentLifecycleService(db, organization_id).assign(
        incident, principal.user_id, request.assigned_to
    )
    db.add(
        AuditLog(
            organization_id=organization_id,
            actor_type="user",
            actor_id=str(principal.user_id),
            action="incident.assigned",
            resource_type="incident",
            resource_id=str(incident.id),
            details={"assigned_to": str(request.assigned_to) if request.assigned_to else None},
        )
    )
    db.commit()
    db.refresh(incident)
    return incident


@router.post("/incidents/{entity_id}/resolve", response_model=IncidentRead)
def resolve_incident(
    entity_id: uuid.UUID,
    request: IncidentResolutionUpdate,
    db: DbSession,
    organization_id: OrganizationId,
    principal: Analyst,
):
    incident = _repo(db, organization_id).get_incident(entity_id)
    if incident is None:
        raise HTTPException(404, "Incident not found")
    try:
        IncidentLifecycleService(db, organization_id).transition(
            incident, principal.user_id, request.status, request.resolution
        )
    except InvalidIncidentTransition as exc:
        raise HTTPException(422, str(exc)) from exc
    db.add(
        AuditLog(
            organization_id=organization_id,
            actor_type="user",
            actor_id=str(principal.user_id),
            action="incident.resolved",
            resource_type="incident",
            resource_id=str(incident.id),
            details={"status": request.status},
        )
    )
    db.commit()
    db.refresh(incident)
    return incident


@router.post("/incidents/{entity_id}/reopen", response_model=IncidentRead)
def reopen_incident(
    entity_id: uuid.UUID,
    request: IncidentReopenRequest,
    db: DbSession,
    organization_id: OrganizationId,
    principal: Analyst,
):
    incident = _repo(db, organization_id).get_incident(entity_id)
    if incident is None:
        raise HTTPException(404, "Incident not found")
    try:
        IncidentLifecycleService(db, organization_id).reopen(
            incident, principal.user_id, request.reason
        )
    except InvalidIncidentTransition as exc:
        raise HTTPException(422, str(exc)) from exc
    db.add(
        AuditLog(
            organization_id=organization_id,
            actor_type="user",
            actor_id=str(principal.user_id),
            action="incident.reopened",
            resource_type="incident",
            resource_id=str(incident.id),
            details={},
        )
    )
    db.commit()
    db.refresh(incident)
    return incident


@router.get("/incidents/{entity_id}/history", response_model=list[IncidentHistoryRead])
def incident_history(
    entity_id: uuid.UUID,
    db: DbSession,
    organization_id: OrganizationId,
    _principal: SecurityReader,
):
    if _repo(db, organization_id).get_incident(entity_id) is None:
        raise HTTPException(404, "Incident not found")
    return _repo(db, organization_id).incident_history(entity_id)


@router.get("/incidents/{entity_id}/enrichments", response_model=list[IncidentEnrichmentRead])
def incident_enrichments(
    entity_id: uuid.UUID,
    db: DbSession,
    organization_id: OrganizationId,
    _principal: SecurityReader,
):
    if _repo(db, organization_id).get_incident(entity_id) is None:
        raise HTTPException(404, "Incident not found")
    return _repo(db, organization_id).incident_enrichments(entity_id)


@router.get("/investigations/{entity_id}", response_model=InvestigationRead)
def get_investigation(
    entity_id: uuid.UUID,
    db: DbSession,
    organization_id: OrganizationId,
    _principal: SecurityReader,
):
    entity = _repo(db, organization_id).get_investigation(entity_id)
    if entity is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return entity


@router.post(
    "/incidents/{entity_id}/investigation",
    response_model=InvestigationRead,
    status_code=201,
)
def create_investigation(
    entity_id: uuid.UUID,
    db: DbSession,
    organization_id: OrganizationId,
    _principal: Analyst,
):
    incident = _repo(db, organization_id).get_incident(entity_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    try:
        investigation = InvestigationService(db, organization_id).create_from_incident(incident)
        investigation_id = investigation.id
        db.commit()
        set_tenant_context(db, organization_id)
        persisted = db.scalar(
            select(Investigation).where(
                Investigation.id == investigation_id,
                Investigation.organization_id == organization_id,
            )
        )
        if persisted is None:
            raise HTTPException(status_code=404, detail="Investigation not found")
        return persisted
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.patch("/investigations/{entity_id}/status", response_model=InvestigationRead)
def update_investigation_status(
    entity_id: uuid.UUID,
    request: InvestigationStatusUpdate,
    db: DbSession,
    organization_id: OrganizationId,
    principal: Analyst,
):
    investigation = _repo(db, organization_id).get_investigation(entity_id)
    if investigation is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    try:
        updated = InvestigationService(db, organization_id).transition(
            investigation, principal.user_id, request.status
        )
    except InvalidInvestigationTransition as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    investigation_id = updated.id
    db.commit()
    set_tenant_context(db, organization_id)
    persisted = db.scalar(
        select(Investigation).where(
            Investigation.id == investigation_id,
            Investigation.organization_id == organization_id,
        )
    )
    if persisted is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return persisted


@router.post("/integrations", response_model=IntegrationRead, status_code=201)
def create_integration(
    request: IntegrationCreate,
    db: DbSession,
    organization_id: OrganizationId,
    role: IntegrationManager,
):
    entity = IntegrationAccount(
        organization_id=organization_id,
        integration_type=request.integration_type,
        name=request.name,
        base_url=str(request.base_url).rstrip("/"),
        credential_reference=request.credential_reference,
        enabled=request.enabled,
        status="configured",
    )
    db.add(entity)
    db.flush()
    db.add(
        AuditLog(
            organization_id=organization_id,
            actor_type="user",
            actor_id=str(role.user_id),
            action="integration.created",
            resource_type="integration_account",
            resource_id=str(entity.id),
            details={"integration_type": entity.integration_type},
        )
    )
    db.commit()
    return entity


@router.get("/integrations", response_model=list[IntegrationRead])
def list_integrations(
    db: DbSession, organization_id: OrganizationId, _principal: IntegrationReader
):
    return IntegrationRepository(db, organization_id).list_all()


@router.get("/integrations/{entity_id}", response_model=IntegrationRead)
def get_integration(
    entity_id: uuid.UUID,
    db: DbSession,
    organization_id: OrganizationId,
    _principal: IntegrationReader,
):
    entity = IntegrationRepository(db, organization_id).get(entity_id)
    if entity is None:
        raise HTTPException(404, "Integration not found")
    return entity


@router.post("/integrations/{entity_id}/test", response_model=JobAccepted, status_code=202)
def test_integration(
    entity_id: uuid.UUID,
    db: DbSession,
    organization_id: OrganizationId,
    role: IntegrationExecutor,
):
    entity = IntegrationRepository(db, organization_id).get(entity_id)
    if entity is None:
        raise HTTPException(404, "Integration not found")
    worker_token = create_worker_token(entity.organization_id, entity.id)
    job = enqueue_task(test_wazuh_connection, str(entity.id), worker_token)
    db.add(
        AuditLog(
            organization_id=organization_id,
            actor_type="user",
            actor_id=str(role.user_id),
            action="integration.test_requested",
            resource_type="integration_account",
            resource_id=str(entity.id),
            details={"job_id": job.id},
        )
    )
    db.commit()
    return JobAccepted(job_id=job.id)


@router.post("/integrations/{entity_id}/sync", response_model=JobAccepted, status_code=202)
def sync_integration(
    entity_id: uuid.UUID,
    db: DbSession,
    organization_id: OrganizationId,
    role: IntegrationExecutor,
):
    entity = IntegrationRepository(db, organization_id).get(entity_id)
    if entity is None:
        raise HTTPException(404, "Integration not found")
    worker_token = create_worker_token(entity.organization_id, entity.id)
    agents_job = enqueue_task(sync_wazuh_agents, str(entity.id), worker_token)
    alerts_job = enqueue_task(sync_wazuh_alerts, str(entity.id), worker_token)
    db.add(
        AuditLog(
            organization_id=organization_id,
            actor_type="user",
            actor_id=str(role.user_id),
            action="integration.sync_requested",
            resource_type="integration_account",
            resource_id=str(entity.id),
            details={"agents_job_id": agents_job.id, "alerts_job_id": alerts_job.id},
        )
    )
    db.commit()
    return JobAccepted(job_id=f"{agents_job.id},{alerts_job.id}")


@router.get("/integrations/{entity_id}/status", response_model=IntegrationStatus)
def integration_status(
    entity_id: uuid.UUID,
    db: DbSession,
    organization_id: OrganizationId,
    _principal: IntegrationReader,
):
    repository = IntegrationRepository(db, organization_id)
    entity = repository.get(entity_id)
    if entity is None:
        raise HTTPException(404, "Integration not found")
    result = IntegrationStatus.model_validate(entity).model_dump()
    result["checkpoints"] = [
        {
            "stream": item.stream,
            "last_position": item.last_position,
            "last_timestamp": item.last_timestamp,
            "cursor": item.cursor,
            "last_success_at": item.last_success_at,
        }
        for item in repository.checkpoints(entity.id)
    ]
    return result


@router.post("/integrations/{entity_id}/rotate-secret", response_model=SecretRotationResponse)
def rotate_integration_secret(
    entity_id: uuid.UUID,
    request: SecretRotationRequest,
    db: DbSession,
    organization_id: OrganizationId,
    principal: SecretRotator,
):
    entity = IntegrationRepository(db, organization_id).get(entity_id)
    if entity is None:
        raise HTTPException(404, "Integration not found")
    try:
        version = get_credential_store().rotate(
            organization_id, entity.credential_reference, request.credentials
        )
    except CredentialStoreError as exc:
        raise HTTPException(502, str(exc)) from exc
    db.add(
        AuditLog(
            organization_id=organization_id,
            actor_type="user",
            actor_id=str(principal.user_id),
            action="integration.secret_rotated",
            resource_type="integration_account",
            resource_id=str(entity.id),
            details={"version": version},
        )
    )
    db.commit()
    return SecretRotationResponse(version=version)


@router.get("/dead-letters", response_model=list[DeadLetterRead])
def list_dead_letters(
    response: Response,
    db: DbSession,
    organization_id: OrganizationId,
    _principal: DeadLetterReader,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    status_filter: str | None = Query(None, alias="status"),
):
    items, total = IntegrationRepository(db, organization_id).dead_letters(
        page, page_size, status_filter
    )
    response.headers["X-Total-Count"] = str(total)
    return items


@router.get("/dead-letters/{entity_id}", response_model=DeadLetterRead)
def get_dead_letter(
    entity_id: uuid.UUID,
    db: DbSession,
    organization_id: OrganizationId,
    _principal: DeadLetterReader,
):
    item = IntegrationRepository(db, organization_id).dead_letter(entity_id)
    if item is None:
        raise HTTPException(404, "Dead letter not found")
    return item


@router.post("/dead-letters/{entity_id}/reprocess", response_model=JobAccepted, status_code=202)
def retry_dead_letter(
    entity_id: uuid.UUID,
    db: DbSession,
    organization_id: OrganizationId,
    _role: DeadLetterReprocessor,
):
    item = IntegrationRepository(db, organization_id).dead_letter(entity_id)
    if item is None or item.status != "pending":
        raise HTTPException(404, "Pending dead letter not found")
    worker_token = create_worker_token(item.organization_id, item.integration_account_id)
    job = enqueue_task(reprocess_dead_letter, str(item.id), worker_token)
    db.add(
        AuditLog(
            organization_id=organization_id,
            actor_type="user",
            actor_id=str(_role.user_id),
            action="dead_letter.reprocess_requested",
            resource_type="dead_letter",
            resource_id=str(item.id),
            details={"job_id": job.id},
        )
    )
    db.commit()
    return JobAccepted(job_id=job.id)


@router.post("/dead-letters/{entity_id}/discard", response_model=DeadLetterRead)
def discard_dead_letter(
    entity_id: uuid.UUID,
    db: DbSession,
    organization_id: OrganizationId,
    _role: DeadLetterDiscarer,
):
    item = IntegrationRepository(db, organization_id).dead_letter(entity_id)
    if item is None or item.status != "pending":
        raise HTTPException(404, "Pending dead letter not found")
    item.status = "discarded"
    db.add(
        AuditLog(
            organization_id=organization_id,
            actor_type="user",
            actor_id=str(_role.user_id),
            action="dead_letter.discarded",
            resource_type="dead_letter",
            resource_id=str(item.id),
            details={},
        )
    )
    db.commit()
    return item
