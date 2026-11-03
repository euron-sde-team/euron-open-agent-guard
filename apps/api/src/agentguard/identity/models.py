"""Agent identities, their credentials, and the keys that sign tokens.

An agent is a workload with its own identity, never a name in a request body. It proves who
it is with a client secret exchanged at ``/oauth/token`` for a short-lived signed token.
The token carries the credential id and the agent's ``token_version``: revoking an agent or
all its credentials bumps the version and kills every token at once, and revoking one
credential kills the tokens minted from it. A suspended or quarantined agent keeps its
tokens but every request is refused on its status, so releasing it needs no new secret.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from agentguard.core.db import Base, OrgScoped, TimestampMixin, new_id

# active: may act. suspended: paused by a person or a limit. quarantined: stopped by a
# threat response, pending investigation. revoked: permanently retired.
AGENT_STATUSES = ("active", "suspended", "quarantined", "revoked")


class Agent(OrgScoped, TimestampMixin, Base):
    __tablename__ = "agents"
    __table_args__ = (UniqueConstraint("org_id", "slug", name="uq_agents_org_slug"),)
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # Stable identifier policies refer to (finance-agent). Unique in the organisation.
    slug: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str] = mapped_column(String(1000), nullable=False, default="")
    # langgraph, crewai, mcp, autogen, python, node, agentos, other.
    framework: Mapped[str] = mapped_column(String(24), nullable=False, default="other")
    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    # Free attributes for ABAC (team, data_access, tier); available to policies as agent.labels.
    labels: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")
    status_reason: Mapped[str | None] = mapped_column(String(500))
    status_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Bumped whenever the agent is suspended, quarantined or revoked: older tokens die.
    token_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # When on, authorize calls must carry an HMAC signature, a timestamp and a fresh nonce.
    require_signed_requests: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    network_policy_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("network_policies.id", ondelete="SET NULL")
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AgentCredential(OrgScoped, TimestampMixin, Base):
    __tablename__ = "agent_credentials"
    __table_args__ = (Index("ix_agent_credentials_agent", "agent_id", "created_at"),)
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False
    )
    # Public half: ag_<12 hex>. The secret half is stored only as a peppered HMAC.
    client_id: Mapped[str] = mapped_column(String(40), nullable=False, unique=True)
    secret_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    # Also signs requests when the agent requires signed requests (sealed, never returned).
    signing_secret_sealed: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    label: Mapped[str] = mapped_column(String(80), nullable=False, default="default")
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Set when a newer credential replaced this one: it keeps working until then.
    grace_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Token exchange is refused from addresses outside these networks (empty: any).
    allowed_cidrs: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )


class SigningKey(TimestampMixin, Base):
    """Installation-wide Ed25519 keys for agent tokens, decision tokens and audit checkpoints.

    The private key is sealed (KMS or the local key). The newest active key signs; retired
    keys stay in the JWKS until every token they signed has expired.
    """

    __tablename__ = "signing_keys"
    kid: Mapped[str] = mapped_column(String(32), primary_key=True)
    public_key: Mapped[str] = mapped_column(Text, nullable=False)
    private_key_sealed: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RequestNonce(Base):
    """Nonces of signed authorize requests, kept for the signature window.

    In Postgres, not the cache: an evicted nonce would let a captured request replay.
    """

    __tablename__ = "request_nonces"
    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), primary_key=True
    )
    nonce: Mapped[str] = mapped_column(String(64), primary_key=True)
    seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )
