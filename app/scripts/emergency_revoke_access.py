import argparse
import uuid
from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.database import SessionLocal, set_tenant_context
from app.models import AuditLog, AuthSession, IdentityProvider, RefreshToken
from app.services import audit_ledger  # noqa: F401 - registers the sealing listener


def revoke_access(
    session: Session,
    organization_id: uuid.UUID,
    *,
    reason: str,
    user_id: uuid.UUID | None = None,
    disable_oidc: bool = False,
) -> dict[str, int]:
    set_tenant_context(session, organization_id)
    session_query = select(AuthSession.id).where(
        AuthSession.organization_id == organization_id,
        AuthSession.revoked_at.is_(None),
    )
    if user_id is not None:
        session_query = session_query.where(AuthSession.user_id == user_id)
    session_ids = list(session.scalars(session_query))
    now = datetime.now(UTC)
    if session_ids:
        session.execute(
            update(AuthSession)
            .where(
                AuthSession.organization_id == organization_id,
                AuthSession.id.in_(session_ids),
            )
            .values(revoked_at=now, revocation_reason=reason[:500])
        )
        session.execute(
            update(RefreshToken)
            .where(
                RefreshToken.organization_id == organization_id,
                RefreshToken.session_id.in_(session_ids),
                RefreshToken.revoked_at.is_(None),
            )
            .values(revoked_at=now)
        )
    provider_count = 0
    if disable_oidc:
        provider_ids = list(
            session.scalars(
                select(IdentityProvider.id).where(
                    IdentityProvider.organization_id == organization_id,
                    IdentityProvider.enabled.is_(True),
                )
            )
        )
        session.execute(
            update(IdentityProvider)
            .where(
                IdentityProvider.organization_id == organization_id,
                IdentityProvider.id.in_(provider_ids),
            )
            .values(enabled=False, updated_at=now)
        )
        provider_count = len(provider_ids)
    session.add(
        AuditLog(
            organization_id=organization_id,
            actor_type="system",
            actor_id="emergency-revocation-cli",
            action="auth.emergency_revocation",
            resource_type="organization" if user_id is None else "user",
            resource_id=str(user_id or organization_id),
            details={
                "reason": reason[:500],
                "sessions_revoked": len(session_ids),
                "identity_providers_disabled": provider_count,
            },
        )
    )
    session.commit()
    return {"sessions_revoked": len(session_ids), "identity_providers_disabled": provider_count}


def main() -> None:
    parser = argparse.ArgumentParser(description="Revoke tenant access in an emergency")
    parser.add_argument("--organization-id", type=uuid.UUID, required=True)
    parser.add_argument("--confirm-organization-id", type=uuid.UUID, required=True)
    parser.add_argument("--user-id", type=uuid.UUID)
    parser.add_argument("--reason", required=True)
    parser.add_argument("--disable-oidc", action="store_true")
    args = parser.parse_args()
    if args.organization_id != args.confirm_organization_id:
        parser.error("organization confirmation does not match")
    with SessionLocal() as session:
        result = revoke_access(
            session,
            args.organization_id,
            reason=args.reason,
            user_id=args.user_id,
            disable_oidc=args.disable_oidc,
        )
    print(
        "Emergency revocation completed: "
        f"sessions={result['sessions_revoked']}, "
        f"providers_disabled={result['identity_providers_disabled']}"
    )


if __name__ == "__main__":
    main()
