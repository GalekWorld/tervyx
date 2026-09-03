import uuid
from collections.abc import Generator

from fastapi import Request
from sqlalchemy import create_engine, text
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
        session.execute(
            text("SELECT set_config('app.current_organization_id', :org, true)"),
            {"org": str(organization_id)},
        )
