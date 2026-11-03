"""API keys and outgoing webhooks."""

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
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from agentguard.core.db import Base, OrgScoped, TimestampMixin, new_id

# Management API keys (automation, CI): read lists and reads everything a dashboard auditor
# can; write also manages agents, tools, policies, secrets and limits. They never authorize
# agent actions: only an agent's own credential does.
SCOPES = ("read", "write")
EVENTS = (
    "decision.denied",
    "approval.requested",
    "approval.decided",
    "threat.detected",
    "incident.opened",
    "incident.updated",
    "agent.status_changed",
    "policy.activated",
    "secret.expiring",
    "tool.changed",
)
# External systems AgentGuard talks to, configured per organisation.
INTEGRATION_KINDS = ("tokenshield", "opa", "siem")


class ApiKey(OrgScoped, TimestampMixin, Base):
    __tablename__ = "api_keys"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(80), nullable=False)
    prefix: Mapped[str] = mapped_column(String(16), nullable=False, unique=True)
    secret_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    scope: Mapped[str] = mapped_column(String(8), nullable=False, default="read")
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )


class Integration(OrgScoped, TimestampMixin, Base):
    """TokenShield budgets, OPA policies or a SIEM sink for one organisation."""

    __tablename__ = "integrations"
    __table_args__ = (UniqueConstraint("org_id", "kind", name="uq_integrations_org_kind"),)
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # tokenshield {url, project, fail_mode}; opa {url, package, rego}; siem {url} (sealed audit records forwarded as NDJSON, with the optional bearer token sealed).
    config: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    secret_sealed: Mapped[bytes | None] = mapped_column(LargeBinary)
    last_error: Mapped[str | None] = mapped_column(String(500))
    last_ok_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Webhook(OrgScoped, TimestampMixin, Base):
    __tablename__ = "webhooks"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    url: Mapped[str] = mapped_column(String(2000), nullable=False)
    events: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    secret_sealed: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    consecutive_failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    disabled_reason: Mapped[str | None] = mapped_column(String(300))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class WebhookDelivery(OrgScoped, Base):
    __tablename__ = "webhook_deliveries"
    __table_args__ = (Index("ix_deliveries_webhook", "webhook_id", "created_at"),)
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    webhook_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("webhooks.id", ondelete="CASCADE"), nullable=False
    )
    event: Mapped[str] = mapped_column(String(48), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    # pending, delivered, failed (will retry), dead (gave up)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    response_status: Mapped[int | None] = mapped_column(Integer)
    response_ms: Mapped[int | None] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    size: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
