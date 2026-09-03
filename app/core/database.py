import uuid
from collections.abc import Generator

from fastapi import Request
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import get_settings


class Base(DeclarativeBase):
    pass


settings = get_settings()
engine = create_engine(
    settings.database_url,
    echo=settings.sql_echo,
    pool_pre_ping=True,
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db(request: Request) -> Generator[Session, None, None]:
    session = SessionLocal()
    request.state.db = session
    try:
        yield session
    finally:
        session.close()


def set_tenant_context(session: Session, organization_id: uuid.UUID) -> None:
    if session.bind is not None and session.bind.dialect.name == "postgresql":
        # Keep the tenant on the Session so transaction-local RLS context can
        # be restored after commit/rollback without leaking it through the
        # pooled connection.
        session.info["tenant_organization_id"] = str(organization_id)
        session.execute(
            text("SELECT set_config('app.current_organization_id', :org, true)"),
            {"org": str(organization_id)},
        )


@event.listens_for(Session, "after_begin")
def _restore_tenant_context(session: Session, transaction, connection) -> None:
    """Restore transaction-local RLS context on every new DB transaction.

    ``set_config(..., true)`` intentionally expires at transaction end.  A
    session may legitimately issue a read after commit, so restore the
    explicitly selected tenant on the next transaction while retaining the
    pool-safety of LOCAL configuration.
    """
    if connection.dialect.name != "postgresql":
        return
    organization_id = session.info.get("tenant_organization_id")
    if organization_id:
        connection.execute(
            text("SELECT set_config('app.current_organization_id', :org, true)"),
            {"org": organization_id},
        )
