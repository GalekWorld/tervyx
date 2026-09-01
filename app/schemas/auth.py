from typing import Literal

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    organization_slug: str = Field(min_length=1, max_length=100)
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=8, max_length=256)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: Literal["bearer"] = "bearer"  # noqa: S105
    expires_in: int


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=40, max_length=512)


class RevokeRequest(RefreshRequest):
    pass
