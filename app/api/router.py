import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, HTTPException, Query, Response, status
from sqlalchemy import select

from app.api.dependencies import Admin, Analyst, DbSession, OrganizationId
from app.core.auth import (
    create_access_token,
    create_refresh_secret,
    create_worker_token,
    get_signing_key_ring,
    hash_refresh_token,
    refresh_token_organization,
    verify_password,
)
from app.core.config import get_settings
from app.core.database import set_tenant_context
from app.integrations.base import AdapterError
from app.integrations.registry import AdapterRegistry
from app.integrations.wazuh import WazuhAdapter
from app.models import AuditLog, IntegrationAccount, Organization, RefreshToken, User
from app.repositories import IntegrationRepository, SecurityRepository
from app.schemas import (
    AlertRead,
    EndpointRead,
    EventIngestRequest,
    IncidentRead,
    IngestResult,
    InvestigationRead,
    SecurityEventRead,
)
from app.schemas.auth import LoginRequest, RefreshRequest, RevokeRequest, TokenResponse
from app.schemas.dlq import DeadLetterRead
from app.schemas.integrations import (
    IntegrationCreate,
    IntegrationRead,
    IntegrationStatus,
    JobAccepted,
)
from app.services.ingestion import IngestionService
from app.workers.tasks import (
    reprocess_dead_letter,
    sync_wazuh_agents,
    sync_wazuh_alerts,
    test_wazuh_connection,
)

router = APIRouter()


def _token_response(db: DbSession, user: User) -> TokenResponse:
    settings = get_settings()
    refresh_secret, token_hash = create_refresh_secret(user.organization_id)
    db.add(
        RefreshToken(
            organization_id=user.organization_id,
            user_id=user.id,
            token_hash=token_hash,
            expires_at=datetime.now(UTC) + timedelta(days=settings.refresh_token_ttl_days),
        )
    )
    return TokenResponse(
        access_token=create_access_token(user.id, user.organization_id, user.role),
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
    response = _token_response(db, user)
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


def _repo(db: DbSession, organization_id: OrganizationId) -> SecurityRepository:
    return SecurityRepository(db, organization_id)


@router.post("/events", response_model=IngestResult, status_code=status.HTTP_201_CREATED)
def ingest_event(
    request: EventIngestRequest, db: DbSession, organization_id: OrganizationId, _role: Analyst
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
def get_endpoint(entity_id: uuid.UUID, db: DbSession, organization_id: OrganizationId):
    entity = _repo(db, organization_id).get_endpoint(entity_id)
    if entity is None:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return entity


@router.get("/alerts", response_model=list[AlertRead])
def list_alerts(
    response: Response,
    db: DbSession,
    organization_id: OrganizationId,
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
def get_alert(entity_id: uuid.UUID, db: DbSession, organization_id: OrganizationId):
    entity = _repo(db, organization_id).get_alert(entity_id)
    if entity is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return entity


@router.get("/incidents", response_model=list[IncidentRead])
def list_incidents(db: DbSession, organization_id: OrganizationId):
    return _repo(db, organization_id).list_incidents()


@router.get("/incidents/{entity_id}", response_model=IncidentRead)
def get_incident(entity_id: uuid.UUID, db: DbSession, organization_id: OrganizationId):
    entity = _repo(db, organization_id).get_incident(entity_id)
    if entity is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return entity


@router.get("/investigations/{entity_id}", response_model=InvestigationRead)
def get_investigation(entity_id: uuid.UUID, db: DbSession, organization_id: OrganizationId):
    entity = _repo(db, organization_id).get_investigation(entity_id)
    if entity is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return entity


@router.post("/integrations", response_model=IntegrationRead, status_code=201)
def create_integration(
    request: IntegrationCreate, db: DbSession, organization_id: OrganizationId, role: Admin
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
def list_integrations(db: DbSession, organization_id: OrganizationId):
    return IntegrationRepository(db, organization_id).list_all()


@router.get("/integrations/{entity_id}", response_model=IntegrationRead)
def get_integration(entity_id: uuid.UUID, db: DbSession, organization_id: OrganizationId):
    entity = IntegrationRepository(db, organization_id).get(entity_id)
    if entity is None:
        raise HTTPException(404, "Integration not found")
    return entity


@router.post("/integrations/{entity_id}/test", response_model=JobAccepted, status_code=202)
def test_integration(
    entity_id: uuid.UUID, db: DbSession, organization_id: OrganizationId, role: Analyst
):
    entity = IntegrationRepository(db, organization_id).get(entity_id)
    if entity is None:
        raise HTTPException(404, "Integration not found")
    worker_token = create_worker_token(entity.organization_id, entity.id)
    job = test_wazuh_connection.delay(str(entity.id), worker_token)
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
    entity_id: uuid.UUID, db: DbSession, organization_id: OrganizationId, role: Analyst
):
    entity = IntegrationRepository(db, organization_id).get(entity_id)
    if entity is None:
        raise HTTPException(404, "Integration not found")
    worker_token = create_worker_token(entity.organization_id, entity.id)
    agents_job = sync_wazuh_agents.delay(str(entity.id), worker_token)
    alerts_job = sync_wazuh_alerts.delay(str(entity.id), worker_token)
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
def integration_status(entity_id: uuid.UUID, db: DbSession, organization_id: OrganizationId):
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


@router.get("/dead-letters", response_model=list[DeadLetterRead])
def list_dead_letters(
    response: Response,
    db: DbSession,
    organization_id: OrganizationId,
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
def get_dead_letter(entity_id: uuid.UUID, db: DbSession, organization_id: OrganizationId):
    item = IntegrationRepository(db, organization_id).dead_letter(entity_id)
    if item is None:
        raise HTTPException(404, "Dead letter not found")
    return item


@router.post("/dead-letters/{entity_id}/reprocess", response_model=JobAccepted, status_code=202)
def retry_dead_letter(
    entity_id: uuid.UUID, db: DbSession, organization_id: OrganizationId, _role: Analyst
):
    item = IntegrationRepository(db, organization_id).dead_letter(entity_id)
    if item is None or item.status != "pending":
        raise HTTPException(404, "Pending dead letter not found")
    worker_token = create_worker_token(item.organization_id, item.integration_account_id)
    job = reprocess_dead_letter.delay(str(item.id), worker_token)
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
    entity_id: uuid.UUID, db: DbSession, organization_id: OrganizationId, _role: Admin
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
