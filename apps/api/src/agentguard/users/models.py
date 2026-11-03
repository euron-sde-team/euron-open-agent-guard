"""People who use the dashboard, and their invitations.

Roles, from most to least power inside an organisation: ``org_admin`` (everything,
including users and settings), ``security_officer`` (agents, policies, tools, secrets,
network, limits, threats, incidents, approvals), ``reviewer`` (decides approvals, reads
agents and decisions) and ``auditor`` (reads everything, changes nothing). A user flagged
``is_global_admin`` also administers the installation (organisations list, installation
signing keys).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from agentguard.core.db import Base, OrgScoped, TimestampMixin, new_id

ROLES = ("auditor", "reviewer", "security_officer", "org_admin")


class User(OrgScoped, TimestampMixin, Base):
    __tablename__ = "users"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    # Null for accounts that only sign in with OIDC.
    password_hash: Mapped[str | None] = mapped_column(Text)
    role: Mapped[str] = mapped_column(String(24), nullable=False, default="reviewer")
    is_global_admin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    disabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # The OIDC "sub" of a federated account, bound on its first OIDC sign-in.
    oidc_subject: Mapped[str | None] = mapped_column(String(255))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Bumped on password change or forced sign-out; sessions carrying an older value die.
    session_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


# One account per email address across the install: sign-in needs no organisation picker.
Index("uq_users_email_lower", func.lower(User.email), unique=True)


class Invitation(OrgScoped, TimestampMixin, Base):
    __tablename__ = "invitations"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    role: Mapped[str] = mapped_column(String(24), nullable=False, default="reviewer")
    # Peppered HMAC of the one-time token in the link; the token itself is never stored.
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    invited_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
