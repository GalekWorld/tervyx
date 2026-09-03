"""Tenant-scoped, deterministic just-in-time privileged access."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.core.auth import PLATFORM_ADMIN_CAPABILITIES, Principal
from app.models import (
    AuditLog,
    AuthSession,
    PlatformAdminEligibility,
    PrivilegedAccessPolicy,
    PrivilegedAccessRequest,
    PrivilegedSession,
)


class PrivilegedAccessError(RuntimeError):
    pass


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


@dataclass(frozen=True)
class PrivilegedAccessToken:
    session: PrivilegedSession
    capabilities: frozenset[str]


class PrivilegedAccessService:
    def __init__(self, session: Session, organization_id: uuid.UUID) -> None:
        self.session = session
        self.organization_id = organization_id

    def policy(self) -> PrivilegedAccessPolicy:
        policy = self.session.scalar(
            select(PrivilegedAccessPolicy).where(
                PrivilegedAccessPolicy.organization_id == self.organization_id
            )
        )
        if policy is None:
            policy = PrivilegedAccessPolicy(organization_id=self.organization_id)
            self.session.add(policy)
            self.session.flush()
        return policy

    def _eligible(self, user_id: uuid.UUID) -> bool:
        return (
            self.session.scalar(
                select(PlatformAdminEligibility.id).where(
                    PlatformAdminEligibility.organization_id == self.organization_id,
                    PlatformAdminEligibility.user_id == user_id,
                    PlatformAdminEligibility.enabled.is_(True),
                )
            )
            is not None
        )

    def _require_step_up(self, principal: Principal, policy: PrivilegedAccessPolicy) -> AuthSession:
        if principal.session_id is None or not principal.mfa_verified:
            raise PrivilegedAccessError("Fresh IdP MFA is required for privileged access")
        auth_session = self.session.scalar(
            select(AuthSession)
            .where(
                AuthSession.id == principal.session_id,
                AuthSession.organization_id == self.organization_id,
                AuthSession.user_id == principal.user_id,
                AuthSession.revoked_at.is_(None),
            )
            .with_for_update()
        )
        now = datetime.now(UTC)
        if auth_session is None or _utc(auth_session.expires_at) <= now:
            raise PrivilegedAccessError("Base session is expired or revoked")
        verified_at = auth_session.mfa_verified_at
        if verified_at is None or _utc(verified_at) < now - timedelta(
            minutes=policy.step_up_max_age_minutes
        ):
            raise PrivilegedAccessError("MFA step-up is stale; reauthenticate with the IdP")
        methods = {str(item).lower() for item in auth_session.mfa_methods}
        allowed = {str(item).lower() for item in policy.allowed_mfa_methods}
        if not methods.intersection(allowed):
            raise PrivilegedAccessError("IdP MFA method is not approved for privileged access")
        return auth_session

    def request(
        self,
        principal: Principal,
        *,
        purpose: str,
        capabilities: list[str],
        duration_minutes: int,
        break_glass: bool = False,
    ) -> PrivilegedAccessRequest:
        policy = self.policy()
        self._require_step_up(principal, policy)
        if not self._eligible(principal.user_id):
            raise PrivilegedAccessError("User is not eligible for Platform Admin JIT access")
        requested = set(capabilities)
        if not requested or not requested.issubset(PLATFORM_ADMIN_CAPABILITIES):
            raise PrivilegedAccessError("Requested privileged capabilities are not allowed")
        if duration_minutes < 1 or duration_minutes > policy.max_duration_minutes:
            raise PrivilegedAccessError("Requested duration violates the privileged access policy")
        if break_glass and not policy.break_glass_enabled:
            raise PrivilegedAccessError("Break-glass is disabled by policy")
        if break_glass and not purpose.lower().startswith("break-glass:"):
            raise PrivilegedAccessError("Break-glass requests require an incident reason")
        now = datetime.now(UTC)
        request = PrivilegedAccessRequest(
            organization_id=self.organization_id,
            requester_id=principal.user_id,
            purpose=purpose,
            requested_capabilities=sorted(requested),
            requested_duration_minutes=duration_minutes,
            break_glass=break_glass,
            status="approved" if break_glass or not policy.approval_required else "requested",
            expires_at=now + timedelta(minutes=duration_minutes),
        )
        self.session.add(request)
        self.session.flush()
        self._audit(principal.user_id, "pam.requested", request, {"break_glass": break_glass})
        if break_glass:
            self._audit(principal.user_id, "pam.break_glass_invoked", request, {})
        return request

    def approve(self, principal: Principal, request_id: uuid.UUID) -> PrivilegedAccessRequest:
        policy = self.policy()
        self._require_step_up(principal, policy)
        if not self._eligible(principal.user_id):
            raise PrivilegedAccessError("Approver is not eligible for Platform Admin")
        request = self._request_for_update(request_id)
        if request.requester_id == principal.user_id:
            raise PrivilegedAccessError("Requester cannot approve their own access")
        if request.status != "requested" or _utc(request.expires_at) <= datetime.now(UTC):
            raise PrivilegedAccessError("Privileged access request cannot be approved")
        request.status = "approved"
        request.approver_id = principal.user_id
        self._audit(principal.user_id, "pam.approved", request, {})
        return request

    def activate(self, principal: Principal, request_id: uuid.UUID) -> PrivilegedAccessToken:
        policy = self.policy()
        base_session = self._require_step_up(principal, policy)
        self._tenant_lock()
        request = self._request_for_update(request_id)
        now = datetime.now(UTC)
        if request.requester_id != principal.user_id or _utc(request.expires_at) <= now:
            raise PrivilegedAccessError("Privileged access request is unavailable")
        if request.status not in {"approved", "active"}:
            raise PrivilegedAccessError("Privileged access request is not approved")
        existing = self.session.scalar(
            select(PrivilegedSession)
            .where(PrivilegedSession.request_id == request.id)
            .with_for_update()
        )
        if existing is not None:
            if existing.status != "active" or _utc(existing.expires_at) <= now:
                raise PrivilegedAccessError("Privileged session is no longer active")
            return PrivilegedAccessToken(existing, frozenset(existing.capabilities))
        privileged = PrivilegedSession(
            organization_id=self.organization_id,
            user_id=principal.user_id,
            base_session_id=base_session.id,
            request_id=request.id,
            capabilities=request.requested_capabilities,
            step_up_verified_at=base_session.mfa_verified_at or now,
            expires_at=min(
                _utc(request.expires_at), now + timedelta(minutes=policy.max_duration_minutes)
            ),
        )
        request.status = "active"
        self.session.add(privileged)
        self.session.flush()
        self._audit(principal.user_id, "pam.activated", request, {"session_id": str(privileged.id)})
        return PrivilegedAccessToken(privileged, frozenset(privileged.capabilities))

    def revoke(
        self, principal: Principal, privileged_session_id: uuid.UUID, *, reason: str
    ) -> None:
        privileged = self.session.scalar(
            select(PrivilegedSession)
            .where(
                PrivilegedSession.id == privileged_session_id,
                PrivilegedSession.organization_id == self.organization_id,
            )
            .with_for_update()
        )
        if privileged is None:
            raise PrivilegedAccessError("Privileged session not found")
        if (
            privileged.user_id != principal.user_id
            and "platform.sessions.revoke" not in principal.privileged_capabilities
        ):
            raise PrivilegedAccessError(
                "Only the holder or a JIT Platform Admin may revoke this session"
            )
        if privileged.status == "active":
            privileged.status = "revoked"
            privileged.revoked_at = datetime.now(UTC)
            privileged.revocation_reason = reason[:500]
            request = self._request_for_update(privileged.request_id)
            request.status = "revoked"
            self._audit(principal.user_id, "pam.revoked", request, {"reason": reason[:500]})

    def _request_for_update(self, request_id: uuid.UUID) -> PrivilegedAccessRequest:
        request = self.session.scalar(
            select(PrivilegedAccessRequest)
            .where(
                PrivilegedAccessRequest.id == request_id,
                PrivilegedAccessRequest.organization_id == self.organization_id,
            )
            .with_for_update()
        )
        if request is None:
            raise PrivilegedAccessError("Privileged access request not found")
        return request

    def _tenant_lock(self) -> None:
        if self.session.bind and self.session.bind.dialect.name == "postgresql":
            self.session.execute(
                text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
                {"key": f"pam:{self.organization_id}"},
            )

    def _audit(
        self,
        actor_id: uuid.UUID,
        action: str,
        request: PrivilegedAccessRequest,
        details: dict[str, object],
    ) -> None:
        self.session.add(
            AuditLog(
                organization_id=self.organization_id,
                actor_type="user",
                actor_id=str(actor_id),
                action=action,
                resource_type="privileged_access_request",
                resource_id=str(request.id),
                details={
                    "requester_id": str(request.requester_id),
                    "capabilities": request.requested_capabilities,
                    "purpose": request.purpose,
                    **details,
                },
            )
        )
