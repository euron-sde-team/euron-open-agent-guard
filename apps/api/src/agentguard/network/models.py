"""Network policies and the outbound connections they decided."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, Boolean, DateTime, Index, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from agentguard.core.db import Base, OrgScoped, TimestampMixin, new_id


class NetworkPolicy(OrgScoped, TimestampMixin, Base):
    """Where an agent may connect.

    ``rules`` is an ordered list; the first rule that matches a destination decides it:
    ``{"action": "allow"|"deny", "host": "*.stripe.com", "cidr": "", "ports": [443],
    "methods": ["GET"]}``. Unmatched destinations get ``default_action``. Private, loopback,
    link-local and cloud metadata addresses are refused unless a rule names them by CIDR.
    """

    __tablename__ = "network_policies"
    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_network_policies_org_name"),)
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    rules: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    default_action: Mapped[str] = mapped_column(String(8), nullable=False, default="deny")
    # The organisation default applies to agents without a policy of their own.
    is_default: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class EgressEvent(OrgScoped, Base):
    __tablename__ = "egress_events"
    __table_args__ = (
        Index("ix_egress_org_at", "org_id", "at"),
        Index("ix_egress_agent_at", "agent_id", "at"),
    )
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    agent_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    run_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    # proxy, http_tool, mcp, webhook, sandbox, classifier.
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    ip: Mapped[str | None] = mapped_column(String(64))
    method: Mapped[str | None] = mapped_column(String(10))
    decision: Mapped[str] = mapped_column(String(8), nullable=False)
    reason: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_name: Mapped[str | None] = mapped_column(String(120))
    bytes_up: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    bytes_down: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
