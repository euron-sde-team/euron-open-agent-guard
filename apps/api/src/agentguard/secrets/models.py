"""Managed secrets: metadata, versions, leases and the access log.

The value of a secret is never returned by any API after it is written. In the ``database``
store each version is encrypted with its own data key (AES-256-GCM), and the data key is
wrapped by KMS or the local key file, so the database alone opens nothing. Other stores keep
the value outside AgentGuard (AWS Secrets Manager, Vault, a host environment variable) and
AgentGuard keeps only the reference.

A secret is used only by AgentGuard itself: injected into an HTTP tool call, an MCP
upstream connection or a sandbox run. It can be bound to destination hosts, so even a
compromised tool configuration cannot send it anywhere else.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from agentguard.core.db import Base, OrgScoped, TimestampMixin, new_id

STORES = ("database", "aws", "vault", "env")


class Secret(OrgScoped, TimestampMixin, Base):
    __tablename__ = "secrets"
    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_secrets_org_name"),)
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id", ondelete="SET NULL")
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    store: Mapped[str] = mapped_column(String(16), nullable=False, default="database")
    # Secrets Manager id, Vault path, or environment variable name (other stores).
    external_ref: Mapped[str | None] = mapped_column(String(500))
    current_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    # After a rotation the previous version stays usable until then (zero-downtime rotation).
    previous_valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    rotation_days: Mapped[int | None] = mapped_column(Integer)
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # When on, it is injected only for agents holding an active lease.
    requires_lease: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Hosts it may be sent to ("api.stripe.com", "*.corp.example"). Empty: any destination
    # the tool and network policy allow.
    allowed_hosts: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Fingerprint (first and last characters, length) shown in place of the value.
    hint: Mapped[str] = mapped_column(String(40), nullable=False, default="")
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )


class SecretVersion(OrgScoped, Base):
    __tablename__ = "secret_versions"
    __table_args__ = (UniqueConstraint("secret_id", "version", name="uq_secret_versions_version"),)
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    secret_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("secrets.id", ondelete="CASCADE"), nullable=False
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    # database store: AES-GCM ciphertext and the wrapped data key.
    ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary)
    wrapped_key: Mapped[bytes | None] = mapped_column(LargeBinary)
    # Other stores: the version id there (Secrets Manager version, Vault version).
    external_version: Mapped[str | None] = mapped_column(String(200))
    hint: Mapped[str] = mapped_column(String(40), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )


class SecretLease(OrgScoped, TimestampMixin, Base):
    """A time-boxed grant of a secret to one agent's executions (temporary credentials)."""

    __tablename__ = "secret_leases"
    __table_args__ = (Index("ix_secret_leases_secret_agent", "secret_id", "agent_id"),)
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    secret_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("secrets.id", ondelete="CASCADE"), nullable=False
    )
    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    max_uses: Mapped[int | None] = mapped_column(Integer)
    uses: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reason: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )


class SecretAccess(OrgScoped, Base):
    __tablename__ = "secret_access_log"
    __table_args__ = (Index("ix_secret_access_secret_at", "secret_id", "at"),)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    secret_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("secrets.id", ondelete="CASCADE"), nullable=False
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    agent_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    decision_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    # http_tool, mcp_upstream, sandbox, rotation, created.
    purpose: Mapped[str] = mapped_column(String(32), nullable=False)
    # used, refused (expired, revoked, no lease, host not allowed).
    outcome: Mapped[str] = mapped_column(String(32), nullable=False, default="used")
    detail: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
