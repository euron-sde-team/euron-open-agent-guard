from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import Field

from agentguard.core.schemas import ApiModel, Email

Role = Literal["auditor", "reviewer", "security_officer", "org_admin"]


class InviteIn(ApiModel):
    email: Email
    role: Role = "reviewer"


class InvitationOut(ApiModel):
    id: uuid.UUID
    email: str
    role: str
    expires_at: datetime
    accepted_at: datetime | None
    created_at: datetime


class InvitationCreated(InvitationOut):
    invite_url: str = Field(description="Shown once: share it if email is not set up")


class UserPatch(ApiModel):
    name: str | None = Field(None, min_length=1, max_length=120)
    role: Role | None = None
    disabled: bool | None = None


class MePatch(ApiModel):
    name: str | None = Field(None, min_length=1, max_length=120)
