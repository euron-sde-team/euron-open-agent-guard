"""Runs, decisions and decision tokens.

A **run** is one execution of an agent (a task, a conversation, a job), named by the agent
(``run_id``) and scoped to it. Limits per run, taint after untrusted content, and loop
detection all hang off it.

A **decision** is the answer to one authorize request, kept with the policy version that
decided it, the reason, the risk and the obligations. Parameters are stored redacted.

A **decision token** lets a tool that runs outside AgentGuard (a ``function`` tool) check
that this exact action was allowed: Ed25519-signed, bound to the action hash, valid for
seconds, and usable once (redeemed online).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from agentguard.core.db import Base, OrgScoped, new_id

DECISIONS = ("allow", "deny", "require_approval", "restrict", "quarantine")


class Run(OrgScoped, Base):
    __tablename__ = "runs"
    __table_args__ = (
        UniqueConstraint("agent_id", "run_key", name="uq_runs_agent_key"),
        Index("ix_runs_agent_active", "agent_id", "ended_at", "last_at"),
    )
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False
    )
    # The agent's own name for the run (a task id, a thread id).
    run_key: Mapped[str] = mapped_column(String(128), nullable=False)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    tool_calls: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    denied: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    data_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    # Set when the run read untrusted content flagged as an injection attempt.
    tainted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    taint: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    # The user the run acts for, as the calling application states it (context, not auth).
    on_behalf_of: Mapped[str | None] = mapped_column(String(320))


class Decision(OrgScoped, Base):
    __tablename__ = "decisions"
    __table_args__ = (
        Index("ix_decisions_org_at", "org_id", "at"),
        Index("ix_decisions_agent_at", "agent_id", "at"),
        Index("ix_decisions_org_decision_at", "org_id", "decision", "at"),
        Index("ix_decisions_run", "run_id"),
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
    # api (authorize), execute, mcp (gateway), egress (proxy), sandbox.
    source: Mapped[str] = mapped_column(String(16), nullable=False, default="api")
    tool: Mapped[str] = mapped_column(String(200), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    resource: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    action_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    # What enforcement returned. In audit mode it is always allow and would_be says what
    # enforce mode would have done.
    decision: Mapped[str] = mapped_column(String(20), nullable=False)
    would_be: Mapped[str] = mapped_column(String(20), nullable=False)
    mode: Mapped[str] = mapped_column(String(8), nullable=False, default="enforce")
    reason_code: Mapped[str] = mapped_column(String(48), nullable=False)
    reasons: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    policy_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    policy_name: Mapped[str | None] = mapped_column(String(120))
    policy_version: Mapped[int | None] = mapped_column(Integer)
    # Every policy rule that matched, with its effect (for explanations and simulation).
    matched: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False, default="low")
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk_factors: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    data_classes: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    obligations: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    approval_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    # Parameters with sensitive values redacted (the raw values are never stored here).
    params: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    # The evaluation input, redacted, so a draft policy can be simulated against history.
    context: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    latency_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    # For execute: none, ok, error, held.
    execution: Mapped[str] = mapped_column(String(16), nullable=False, default="none")
    execution_meta: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    on_behalf_of: Mapped[str | None] = mapped_column(String(320))


class DecisionToken(OrgScoped, Base):
    __tablename__ = "decision_tokens"
    jti: Mapped[str] = mapped_column(String(48), primary_key=True)
    decision_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("decisions.id", ondelete="CASCADE"), nullable=False
    )
    action_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    single_use: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
