import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.auth import ALL_CAPABILITIES


class IdentityProviderCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider_type: Literal["entra", "okta", "google", "keycloak", "generic"]
    name: str = Field(min_length=1, max_length=255)
    issuer: str = Field(min_length=8, max_length=2048)
    client_id: str = Field(min_length=1, max_length=255)
    client_secret_reference: str = Field(min_length=1, max_length=500)
    scopes: list[str] = Field(default=["openid", "profile", "email"], max_length=20)
    allowed_redirect_uris: list[str] = Field(min_length=1, max_length=20)
    enforce_mfa: bool = True
    provider_tenant_id: str | None = Field(default=None, max_length=255)

    @field_validator("issuer", "allowed_redirect_uris")
    @classmethod
    def require_https(cls, value: Any) -> Any:
        values = value if isinstance(value, list) else [value]
        if any(not item.startswith("https://") for item in values):
            raise ValueError("OIDC URLs must use HTTPS")
        return value


class IdentityProviderRead(BaseModel):
    id: uuid.UUID
    provider_type: str
    name: str
    issuer: str
    client_id: str
    scopes: list[str]
    allowed_redirect_uris: list[str]
    enabled: bool
    enforce_mfa: bool
    provider_tenant_id: str | None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class OIDCAuthorizeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    organization_slug: str = Field(min_length=1, max_length=100)
    provider_name: str = Field(min_length=1, max_length=255)
    redirect_uri: str = Field(min_length=8, max_length=2048)


class OIDCAuthorizeResponse(BaseModel):
    authorization_url: str
    expires_in: int


class OIDCCallbackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    state: str = Field(min_length=40, max_length=1024)
    code: str = Field(min_length=1, max_length=4096)
    redirect_uri: str = Field(min_length=8, max_length=2048)


class CapabilityGrantRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    effect: Literal["allow", "deny"]


class CapabilityGrantRead(BaseModel):
    capability: str
    effect: str

    model_config = ConfigDict(from_attributes=True)

    @field_validator("capability")
    @classmethod
    def known_capability(cls, value: str) -> str:
        if value not in ALL_CAPABILITIES:
            raise ValueError("Unknown capability")
        return value


class SessionRead(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    auth_method: str
    mfa_verified: bool
    expires_at: datetime
    revoked_at: datetime | None
    revocation_reason: str | None

    model_config = ConfigDict(from_attributes=True)


class SecretRotationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    credentials: dict[str, Any] = Field(min_length=1, max_length=50)


class SecretRotationResponse(BaseModel):
    status: Literal["rotated"] = "rotated"
    version: str


class PrivilegedAccessRequestCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    purpose: str = Field(min_length=8, max_length=500)
    capabilities: list[str] = Field(min_length=1, max_length=4)
    duration_minutes: int = Field(ge=1, le=120)
    break_glass: bool = False


class PrivilegedAccessApproval(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PrivilegedAccessRevoke(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=3, max_length=500)


class PrivilegedAccessRead(BaseModel):
    id: uuid.UUID
    requester_id: uuid.UUID
    approver_id: uuid.UUID | None
    requested_capabilities: list[str]
    purpose: str
    break_glass: bool
    status: str
    expires_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PrivilegedTokenResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"  # noqa: S105 - protocol constant
    privileged_session_id: uuid.UUID
    expires_in: int
