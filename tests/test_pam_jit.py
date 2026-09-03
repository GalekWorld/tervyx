from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.auth import Principal, create_access_token
from app.models import (
    AuditLog,
    AuthSession,
    PlatformAdminEligibility,
    PrivilegedAccessPolicy,
    PrivilegedSession,
    User,
)
from app.services.audit_ledger import AuditLedgerService
from app.services.pam import PrivilegedAccessError, PrivilegedAccessService
from tests.conftest import OTHER_ORG_ID, OTHER_USER_ID, TEST_ORG_ID, TEST_USER_ID


def _principal(session: Session, user_id=TEST_USER_ID, organization_id=TEST_ORG_ID) -> Principal:
    now = datetime.now(UTC)
    auth_session = AuthSession(
        organization_id=organization_id,
        user_id=user_id,
        auth_method="oidc:fido2",
        mfa_verified=True,
        mfa_verified_at=now,
        mfa_methods=["fido2"],
        expires_at=now + timedelta(hours=1),
        last_seen_at=now,
    )
    session.add(auth_session)
    session.flush()
    return Principal(
        user_id=user_id,
        organization_id=organization_id,
        role="admin",
        session_id=auth_session.id,
        mfa_verified=True,
    )


def _eligible(session: Session, user_id=TEST_USER_ID, organization_id=TEST_ORG_ID) -> None:
    session.add(
        PlatformAdminEligibility(
            organization_id=organization_id,
            user_id=user_id,
            enabled=True,
        )
    )
    session.flush()


def test_pam_requires_fresh_mfa_eligibility_approval_and_is_idempotent(session: Session) -> None:
    requester = _principal(session)
    approver_user = User(
        organization_id=TEST_ORG_ID,
        email="approver@test.local",
        display_name="Approver",
        role="admin",
    )
    session.add(approver_user)
    session.flush()
    approver = _principal(session, approver_user.id)
    _eligible(session)
    _eligible(session, approver_user.id)
    service = PrivilegedAccessService(session, TEST_ORG_ID)

    request = service.request(
        requester,
        purpose="Investigate production access incident",
        capabilities=["platform.audit.export"],
        duration_minutes=10,
    )
    assert request.status == "requested"
    with pytest.raises(PrivilegedAccessError, match="cannot approve"):
        service.approve(requester, request.id)
    service.approve(approver, request.id)
    first = service.activate(requester, request.id)
    second = service.activate(requester, request.id)
    session.commit()

    assert first.session.id == second.session.id
    assert first.capabilities == frozenset({"platform.audit.export"})
    assert session.scalar(
        select(PrivilegedSession).where(PrivilegedSession.request_id == request.id)
    )
    assert AuditLedgerService(session).verify(TEST_ORG_ID).valid
    assert session.scalar(select(AuditLog).where(AuditLog.action == "pam.activated")) is not None


def test_pam_expiration_revocation_and_cross_tenant_are_enforced(session: Session) -> None:
    principal = _principal(session)
    _eligible(session)
    service = PrivilegedAccessService(session, TEST_ORG_ID)
    service.policy().break_glass_enabled = True
    request = service.request(
        principal,
        purpose="Break-glass: production compromise response",
        capabilities=["platform.sessions.revoke"],
        duration_minutes=5,
        break_glass=True,
    )
    request.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    with pytest.raises(PrivilegedAccessError, match="unavailable"):
        service.activate(principal, request.id)

    request.expires_at = datetime.now(UTC) + timedelta(minutes=5)
    active = service.activate(principal, request.id).session
    service.revoke(principal, active.id, reason="contained")
    session.commit()
    assert active.status == "revoked"

    foreign = _principal(session, OTHER_USER_ID, OTHER_ORG_ID)
    foreign_service = PrivilegedAccessService(session, OTHER_ORG_ID)
    with pytest.raises(PrivilegedAccessError, match="not found"):
        foreign_service.revoke(foreign, active.id, reason="cross tenant")


def test_pam_api_requires_separate_jit_token_and_rejects_stale_step_up(
    client: TestClient, session: Session
) -> None:
    principal = _principal(session)
    _eligible(session)
    session.commit()
    client.headers["Authorization"] = "Bearer " + create_access_token(
        TEST_USER_ID,
        TEST_ORG_ID,
        "admin",
        session_id=principal.session_id,
        mfa_verified=True,
    )
    response = client.post(
        "/api/v1/platform-admin/requests",
        json={
            "purpose": "Export audit evidence for an incident",
            "capabilities": ["platform.audit.export"],
            "duration_minutes": 5,
        },
    )
    assert response.status_code == 201
    request_id = response.json()["id"]

    # Approval is disabled only for this tenant's test policy; activation still
    # relies on its separate, session-bound JIT token.
    policy = session.scalar(
        select(PrivilegedAccessPolicy).where(PrivilegedAccessPolicy.organization_id == TEST_ORG_ID)
    )
    assert policy is not None
    policy.approval_required = False
    session.commit()
    # Existing request still awaits approval: it cannot be activated as a bypass.
    assert client.post(f"/api/v1/platform-admin/requests/{request_id}/activate").status_code == 403

    stale = session.get(AuthSession, principal.session_id)
    assert stale is not None
    stale.mfa_verified_at = datetime.now(UTC) - timedelta(hours=1)
    session.commit()
    rejected = client.post(
        "/api/v1/platform-admin/requests",
        json={
            "purpose": "Export audit evidence for another incident",
            "capabilities": ["platform.audit.export"],
            "duration_minutes": 5,
        },
    )
    assert rejected.status_code == 403
