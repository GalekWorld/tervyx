import logging
import time
import uuid
from typing import cast

from fastapi import Request
from fastapi.responses import JSONResponse
from redis import Redis
from redis.exceptions import RedisError

from app.core.config import get_settings
from app.core.observability import HTTP_DURATION, HTTP_REQUESTS

logger = logging.getLogger(__name__)


async def security_middleware(request: Request, call_next):
    settings = get_settings()
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))[:128]
    request.state.request_id = request_id
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            declared_length = int(content_length)
        except ValueError:
            return JSONResponse(
                status_code=400,
                content={"detail": "Invalid Content-Length", "request_id": request_id},
            )
        if declared_length < 0 or declared_length > settings.max_request_body_bytes:
            return JSONResponse(
                status_code=413,
                content={"detail": "Request body too large", "request_id": request_id},
            )
    if request.method in {"POST", "PUT", "PATCH"}:
        body = await request.body()
        if len(body) > settings.max_request_body_bytes:
            return JSONResponse(
                status_code=413,
                content={"detail": "Request body too large", "request_id": request_id},
            )
    if settings.rate_limit_enabled and not request.url.path.startswith(("/health", "/metrics")):
        client = request.client.host if request.client else "unknown"
        key = f"rate:{client}:{request.url.path}"
        try:
            redis = Redis.from_url(settings.celery_broker_url)
            count = cast(int, redis.incr(key))
            if count == 1:
                redis.expire(key, settings.rate_limit_window_seconds)
            if count > settings.rate_limit_requests:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded", "request_id": request_id},
                    headers={"Retry-After": str(settings.rate_limit_window_seconds)},
                )
        except RedisError:
            return JSONResponse(
                status_code=503,
                content={"detail": "Rate limiter unavailable", "request_id": request_id},
            )
    started = time.monotonic()
    response = await call_next(request)
    route = request.scope.get("route")
    path = getattr(route, "path", request.url.path)
    duration_seconds = time.monotonic() - started
    HTTP_REQUESTS.labels(request.method, path, str(response.status_code)).inc()
    HTTP_DURATION.labels(request.method, path).observe(duration_seconds)
    logger.info(
        "http_request_completed",
        extra={
            "request_id": request_id,
            "method": request.method,
            "path": path,
            "status_code": response.status_code,
            "duration_ms": round(duration_seconds * 1000),
        },
    )
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    return response
