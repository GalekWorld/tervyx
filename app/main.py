from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from redis import Redis
from sqlalchemy import text
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api.router import router
from app.core.auth import get_signing_key_ring
from app.core.config import get_settings
from app.core.database import SessionLocal, engine
from app.core.logging import configure_logging
from app.core.middleware import security_middleware
from app.core.observability import configure_telemetry


def create_app() -> FastAPI:
    configure_logging()
    settings = get_settings()
    production = settings.app_env == "production"
    application = FastAPI(
        title=settings.app_name,
        debug=settings.debug,
        version="0.1.0",
        description="Hardened multi-tenant Autonomous SOC API",
        docs_url=None if production else "/docs",
        redoc_url=None if production else "/redoc",
        openapi_url=None if production else "/openapi.json",
    )
    application.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts_list)
    if settings.cors_origins_list:
        application.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins_list,
            allow_credentials=False,
            allow_methods=["GET", "POST"],
            allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        )
    application.middleware("http")(security_middleware)
    application.include_router(router, prefix=settings.api_v1_prefix)

    @application.get("/.well-known/jwks.json", include_in_schema=False)
    def public_jwks():
        return get_signing_key_ring().jwks()

    @application.get("/health", tags=["system"])
    @application.get("/health/live", tags=["system"])
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @application.get("/health/ready", tags=["system"])
    def readiness():
        try:
            with SessionLocal() as session:
                session.execute(text("SELECT 1"))
            Redis.from_url(settings.celery_broker_url).ping()
            return {"status": "ready"}
        except Exception:
            return JSONResponse(status_code=503, content={"status": "not_ready"})

    @application.get("/metrics", include_in_schema=False)
    def metrics() -> Response:
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    @application.exception_handler(Exception)
    async def unhandled_error(request: Request, exc: Exception):
        return JSONResponse(
            status_code=500,
            content={
                "detail": "Internal server error",
                "request_id": getattr(request.state, "request_id", None),
            },
        )

    configure_telemetry(application, engine)

    return application


app = create_app()
