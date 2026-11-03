"""Signed-out sessions, sign-in failure counters and OIDC providers."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, Integer, LargeBinary, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from agentguard.core.db import Base, OrgScoped, TimestampMixin, new_id


class RevokedSession(Base):
    """One row per signed-out session token (its ``jti``).

    Kept in Postgres rather than the cache: cache eviction must never bring a signed-out
    session back. Rows past ``expires_at`` are pruned on later sign-outs.
    """

    __tablename__ = "revoked_sessions"
    jti: Mapped[str] = mapped_column(String(64), primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )


class LoginFailure(Base):
    """Failed sign-ins per (account, client address) and per account.

    Keyed by an HMAC so emails and addresses are not stored in the clear. Locking per
    address means a stranger guessing passwords locks only their own address out, not the
    owner; the per-account counter has a much higher threshold and stops distributed
    guessing.
    """

    __tablename__ = "login_failures"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    window_started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class OidcProvider(OrgScoped, TimestampMixin, Base):
    """Single sign-on for one organisation through any OpenID Connect provider."""

    __tablename__ = "oidc_providers"
    __table_args__ = (UniqueConstraint("org_id", name="uq_oidc_providers_org"),)
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    issuer: Mapped[str] = mapped_column(String(500), nullable=False)
    client_id: Mapped[str] = mapped_column(String(255), nullable=False)
    client_secret_sealed: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    # Only these email domains may sign in (empty: any address the provider vouches for).
    allowed_domains: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    # A claim (groups, roles) and a map from its values to dashboard roles.
    role_claim: Mapped[str] = mapped_column(String(64), nullable=False, default="groups")
    role_map: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    # Role of a first-time user whose claims map to nothing; empty refuses them.
    default_role: Mapped[str] = mapped_column(String(24), nullable=False, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
