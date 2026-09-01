import uuid
from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.auth import ROLES, Principal, decode_token
from app.core.database import get_db, set_tenant_context
from app.models import User

DbSession = Annotated[Session, Depends(get_db)]
bearer = HTTPBearer(auto_error=False)


def get_principal(
    db: DbSession, credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]
) -> Principal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = decode_token(credentials.credentials)
    try:
        principal = Principal(
            user_id=uuid.UUID(payload["sub"]),
            organization_id=uuid.UUID(payload["org"]),
            role=payload["role"],
        )
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=401, detail="Invalid token claims") from exc
    if principal.role not in ROLES:
        raise HTTPException(status_code=403, detail="Unknown role")
    set_tenant_context(db, principal.organization_id)
    user = db.scalar(
        select(User).where(
            User.id == principal.user_id,
            User.organization_id == principal.organization_id,
            User.is_active.is_(True),
        )
    )
    if user is None or user.role != principal.role:
        raise HTTPException(status_code=401, detail="User is inactive or token is stale")
    return principal


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
