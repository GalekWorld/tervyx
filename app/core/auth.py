import hashlib
import json
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from fastapi import HTTPException, status
from jwt.algorithms import RSAAlgorithm
from pwdlib import PasswordHash

from app.core.config import get_settings

ROLES = {"viewer": 1, "analyst": 2, "admin": 3}
password_hash = PasswordHash.recommended()


@dataclass(frozen=True)
class Principal:
    user_id: uuid.UUID
    organization_id: uuid.UUID
    role: str


@dataclass(frozen=True)
class SigningKeyRing:
    active_kid: str
    private_key: str
    public_keys: dict[str, str]

    def jwks(self) -> dict[str, list[dict[str, Any]]]:
        keys = []
        for kid, public_key in self.public_keys.items():
            key_object = load_pem_public_key(public_key.encode("utf-8"))
            jwk = json.loads(RSAAlgorithm.to_jwk(key_object))
            jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
            keys.append(jwk)
        return {"keys": keys}


def _read_key(path: str, label: str) -> str:
    if not path:
        raise RuntimeError(f"{label} path is not configured")
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"{label} cannot be loaded") from exc


@lru_cache
def get_signing_key_ring() -> SigningKeyRing:
    settings = get_settings()
    if not settings.jwt_active_kid:
        raise RuntimeError("JWT_ACTIVE_KID is not configured")
    private_key = _read_key(settings.jwt_private_key_path, "JWT private key")
    active_public_key = _read_key(settings.jwt_public_key_path, "JWT public key")
    try:
        configured = json.loads(settings.jwt_verification_keys_json)
    except json.JSONDecodeError as exc:
        raise RuntimeError("JWT verification key set is invalid") from exc
    if not isinstance(configured, dict) or not all(
        isinstance(kid, str) and isinstance(value, str) for kid, value in configured.items()
    ):
        raise RuntimeError("JWT verification key set must map kid to PEM")
    public_keys = dict(configured)
    public_keys[settings.jwt_active_kid] = active_public_key
    return SigningKeyRing(settings.jwt_active_kid, private_key, public_keys)


def _encode(payload: dict[str, Any]) -> str:
    key_ring = get_signing_key_ring()
    return str(
        jwt.encode(
            payload,
            key_ring.private_key,
            algorithm="RS256",
            headers={"kid": key_ring.active_kid, "typ": "JWT"},
        )
    )


def create_access_token(user_id: uuid.UUID, organization_id: uuid.UUID, role: str) -> str:
    settings = get_settings()
    now = datetime.now(UTC)
    return _encode(
        {
            "sub": str(user_id),
            "org": str(organization_id),
            "role": role,
            "iss": settings.jwt_issuer,
            "aud": settings.jwt_audience,
            "iat": now,
            "exp": now + timedelta(minutes=settings.access_token_ttl_minutes),
            "jti": str(uuid.uuid4()),
            "type": "access",
        }
    )


def create_worker_token(organization_id: uuid.UUID, integration_id: uuid.UUID) -> str:
    settings = get_settings()
    now = datetime.now(UTC)
    return _encode(
        {
            "sub": "celery",
            "org": str(organization_id),
            "integration": str(integration_id),
            "iss": settings.jwt_issuer,
            "aud": "autonomous-soc-worker",
            "iat": now,
            "exp": now + timedelta(hours=24),
            "jti": str(uuid.uuid4()),
            "type": "worker",
        }
    )


def decode_token(token: str, *, audience: str | None = None) -> dict[str, Any]:
    settings = get_settings()
    try:
        header = jwt.get_unverified_header(token)
        if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
            raise jwt.InvalidAlgorithmError("Unexpected JWT algorithm")
        public_key = get_signing_key_ring().public_keys.get(header["kid"])
        if public_key is None:
            raise jwt.InvalidKeyError("Unknown signing key")
        return jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            issuer=settings.jwt_issuer,
            audience=audience or settings.jwt_audience,
            options={"require": ["exp", "iat", "jti", "sub", "org", "type"]},
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def create_refresh_secret(organization_id: uuid.UUID) -> tuple[str, str]:
    token = f"{organization_id}.{secrets.token_urlsafe(48)}"
    return token, hash_refresh_token(token)


def refresh_token_organization(token: str) -> uuid.UUID:
    try:
        organization, secret = token.split(".", 1)
        if len(secret) < 40:
            raise ValueError
        return uuid.UUID(organization)
    except (ValueError, AttributeError) as exc:
        raise HTTPException(status_code=401, detail="Invalid refresh token") from exc


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def verify_password(password: str, encoded: str) -> bool:
    return password_hash.verify(password, encoded)


def hash_password(password: str) -> str:
    return password_hash.hash(password)
