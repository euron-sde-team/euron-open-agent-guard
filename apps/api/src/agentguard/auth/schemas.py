from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import Field

from agentguard.core.schemas import ApiModel, Email


class LoginRequest(ApiModel):
    email: Email
    password: str = Field(min_length=1, max_length=256)


class SignupRequest(ApiModel):
    org_name: str = Field(min_length=1, max_length=120, description="Your company or team")
    name: str = Field(min_length=1, max_length=120)
    email: Email
    password: str = Field(min_length=10, max_length=256)


class AcceptInvitation(ApiModel):
    token: str = Field(min_length=10, max_length=200)
    name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=10, max_length=256)


class UserOut(ApiModel):
    id: uuid.UUID
    org_id: uuid.UUID
    email: str
    name: str
    role: str
    is_global_admin: bool
    disabled: bool
    sso: bool = False
    last_seen_at: datetime | None
    last_login_at: datetime | None
    created_at: datetime


class SignInOut(ApiModel):
    user: UserOut
    org_slug: str
    session_token: str = Field(description="Bearer token for API clients; browsers use the cookie")
    expires_in_s: int


class PasswordChange(ApiModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=10, max_length=256)


class InvitationPreview(ApiModel):
    email: str
    role: str
    org_name: str
