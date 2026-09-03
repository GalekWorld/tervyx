import base64
import hashlib
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt
from jwt.api_jwk import PyJWK

from app.core.network import validate_outbound_url
from app.integrations.resilience import (
    Bulkhead,
    CircuitBreaker,
    ConnectorBulkheadFull,
    RetryPolicy,
    get_connector_resilience,
)
from app.models import IdentityProvider


class OIDCError(RuntimeError):
    pass


class OIDCTransientError(OIDCError):
    """A provider transport/server error safe for bounded retry."""


@dataclass(frozen=True)
class OIDCIdentity:
    subject: str
    email: str | None
    display_name: str
    provider_tenant_id: str | None
    mfa_verified: bool
    claims: dict[str, Any]
    mfa_methods: frozenset[str] = frozenset()


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


class OIDCClient:
    def __init__(
        self,
        provider: IdentityProvider,
        client_secret: str,
        *,
        timeout: float = 10.0,
        max_retries: int = 2,
        client: httpx.Client | None = None,
        sleep: Callable[[float], None] = time.sleep,
        policy: RetryPolicy | None = None,
        circuit_breaker: CircuitBreaker | None = None,
        bulkhead: Bulkhead | None = None,
        resilience_key: str | None = None,
    ) -> None:
        self.provider = provider
        self.client_secret = client_secret
        self.max_retries = max_retries
        self.sleep = sleep
        self._owns_client = client is None
        self._client = client or httpx.Client(timeout=httpx.Timeout(timeout))
        shared = (
            get_connector_resilience(
                f"oidc:{resilience_key or provider.issuer}", max_attempts=max_retries + 1
            )
            if self._owns_client
            else None
        )
        self.policy = policy or (
            shared.policy
            if shared
            else RetryPolicy(max_attempts=max_retries + 1, base_delay_seconds=1.0)
        )
        self.circuit_breaker = circuit_breaker or (
            shared.circuit_breaker if shared else CircuitBreaker()
        )
        self.bulkhead = bulkhead or (shared.bulkhead if shared else Bulkhead())
        self._metadata: dict[str, Any] | None = None

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def discovery(self) -> dict[str, Any]:
        if self._metadata is not None:
            return self._metadata
        issuer = validate_outbound_url(self.provider.issuer).rstrip("/")
        response = self._request("GET", f"{issuer}/.well-known/openid-configuration")
        try:
            metadata = response.json()
            if metadata["issuer"].rstrip("/") != issuer:
                raise OIDCError("OIDC discovery issuer mismatch")
            for field in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
                metadata[field] = validate_outbound_url(str(metadata[field]))
        except (ValueError, KeyError, TypeError) as exc:
            raise OIDCError("Malformed OIDC discovery response") from exc
        self._metadata = metadata
        return metadata

    def authorization_url(
        self,
        *,
        state: str,
        nonce: str,
        redirect_uri: str,
        code_challenge: str,
    ) -> str:
        metadata = self.discovery()
        query = urlencode(
            {
                "client_id": self.provider.client_id,
                "response_type": "code",
                "redirect_uri": redirect_uri,
                "response_mode": "query",
                "scope": " ".join(self.provider.scopes or ["openid", "profile", "email"]),
                "state": state,
                "nonce": nonce,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            }
        )
        return f"{metadata['authorization_endpoint']}?{query}"

    def exchange_code(
        self, *, code: str, redirect_uri: str, code_verifier: str, nonce: str
    ) -> OIDCIdentity:
        metadata = self.discovery()
        response = self._request(
            "POST",
            metadata["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "client_id": self.provider.client_id,
                "client_secret": self.client_secret,
                "code": code,
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier,
            },
        )
        try:
            id_token = response.json()["id_token"]
        except (ValueError, KeyError, TypeError) as exc:
            raise OIDCError("OIDC token response is missing an ID token") from exc
        return self.validate_id_token(str(id_token), nonce=nonce)

    def validate_id_token(self, token: str, *, nonce: str | None = None) -> OIDCIdentity:
        metadata = self.discovery()
        try:
            header = jwt.get_unverified_header(token)
            algorithm = header.get("alg")
            kid = header.get("kid")
            if algorithm not in {"RS256", "ES256"} or not isinstance(kid, str):
                raise OIDCError("Unsupported OIDC signing key")
            jwks = self._request("GET", metadata["jwks_uri"]).json()["keys"]
            jwk = next(item for item in jwks if item.get("kid") == kid)
            key = PyJWK.from_dict(jwk).key
            claims = jwt.decode(
                token,
                key,
                algorithms=[algorithm],
                issuer=metadata["issuer"],
                audience=self.provider.client_id,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except OIDCError:
            raise
        except (jwt.PyJWTError, ValueError, KeyError, StopIteration, TypeError) as exc:
            raise OIDCError("OIDC ID token validation failed") from exc
        if nonce is not None and not secrets.compare_digest(str(claims.get("nonce", "")), nonce):
            raise OIDCError("OIDC nonce validation failed")

        provider_tenant_id = str(claims.get("tid")) if claims.get("tid") else None
        subject = str(claims["sub"])
        if self.provider.provider_type == "entra":
            oid = claims.get("oid")
            if not oid or not provider_tenant_id:
                raise OIDCError("Entra ID token is missing oid/tid claims")
            if (
                self.provider.provider_tenant_id
                and provider_tenant_id != self.provider.provider_tenant_id
            ):
                raise OIDCError("Entra tenant claim mismatch")
            subject = f"{provider_tenant_id}:{oid}"

        amr = {str(item).lower() for item in claims.get("amr", [])}
        mfa_verified = bool(
            amr.intersection(
                {
                    "mfa",
                    "ngcmfa",
                    "wiaormfa",
                    "fido",
                    "fido2",
                    "webauthn",
                    "passkey",
                    "hardware",
                }
            )
        )
        email = claims.get("email") or claims.get("preferred_username") or claims.get("upn")
        return OIDCIdentity(
            subject=subject,
            email=str(email).lower() if email else None,
            display_name=str(claims.get("name") or email or subject),
            provider_tenant_id=provider_tenant_id,
            mfa_verified=mfa_verified,
            mfa_methods=frozenset(amr),
            claims=claims,
        )

    def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        for attempt in range(self.policy.max_attempts):
            self.circuit_breaker.before_call()
            try:
                with self.bulkhead.slot():
                    response = self._client.request(method, url, **kwargs)
            except httpx.TransportError as exc:
                self.circuit_breaker.record_failure()
                if attempt + 1 >= self.policy.max_attempts:
                    raise OIDCTransientError("OIDC provider transport failure") from exc
                self.sleep(self.policy.delay(attempt))
                continue
            except ConnectorBulkheadFull as exc:
                raise OIDCError("OIDC connector concurrency limit reached") from exc
            if response.status_code in {429} or response.status_code >= 500:
                self.circuit_breaker.record_failure()
                if attempt + 1 < self.policy.max_attempts:
                    retry_after = None
                    try:
                        retry_after = float(response.headers.get("Retry-After", ""))
                    except ValueError:
                        pass
                    self.sleep(self.policy.delay(attempt, retry_after))
                    continue
            if response.status_code >= 400:
                if response.status_code == 429 or response.status_code >= 500:
                    raise OIDCTransientError(
                        f"OIDC provider request failed ({response.status_code})"
                    )
                raise OIDCError(f"OIDC provider request failed ({response.status_code})")
            self.circuit_breaker.record_success()
            return response
        raise OIDCTransientError("OIDC provider request failed")
