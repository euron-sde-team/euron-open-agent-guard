"""Threat events and the behavioural baselines they are measured against."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Index, String, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from agentguard.core.db import Base, OrgScoped, new_id

SEVERITIES = ("low", "medium", "high", "critical")
KINDS = (
    "prompt_injection",
    "data_exfiltration",
    "credential_leakage",
    "tool_abuse",
    "privilege_escalation",
    "agent_loop",
    "unauthorized_access",
    "suspicious_network",
    "malicious_tool_output",
    "cross_tenant",
    "resource_exhaustion",
    "agent_impersonation",
    "behavioural_anomaly",
    "tool_definition_changed",
)
# rule (deterministic), behavioural (baseline deviation), ai (classifier).
DETECTORS = ("rule", "behavioural", "ai")
STATUSES = ("open", "acknowledged", "resolved", "false_positive")


class ThreatEvent(OrgScoped, Base):
    __tablename__ = "threat_events"
    __table_args__ = (
        Index("ix_threats_org_at", "org_id", "at"),
        Index("ix_threats_agent_at", "agent_id", "at"),
        # One open event per (agent, kind, dedupe key): a burst does not flood the list.
        Index(
            "uq_threats_open_dedupe",
            "org_id",
            "dedupe_key",
            unique=True,
            postgresql_where=text("status = 'open' AND dedupe_key IS NOT NULL"),
        ),
    )
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    agent_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agents.id", ondelete="SET NULL")
    )
    run_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("runs.id", ondelete="SET NULL")
    )
    decision_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    detector: Mapped[str] = mapped_column(String(16), nullable=False, default="rule")
    rule: Mapped[str] = mapped_column(String(64), nullable=False)
    summary: Mapped[str] = mapped_column(String(500), nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    occurrences: Mapped[int] = mapped_column(nullable=False, default=1)
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    dedupe_key: Mapped[str | None] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="open")
    # What the automatic response did: quarantined, revoked, incident, notified.
    responses: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    incident_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))


class AgentBaseline(OrgScoped, Base):
    """An agent's normal behaviour, recomputed hourly from its decisions."""

    __tablename__ = "agent_baselines"
    __table_args__ = (UniqueConstraint("agent_id", name="uq_agent_baselines_agent"),)
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False
    )
    computed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    # hourly call counts (median and MAD), tools seen, destinations seen, hours observed.
    stats: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
