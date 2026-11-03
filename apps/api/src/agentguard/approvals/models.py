"""Approval requests, the votes on them, and their append-only history.

An approval is bound to the **action hash** of the exact request (agent, tool, action,
resource and canonical parameters). Approving a request approves that hash and nothing
else; an agent that changes one parameter makes a new request. The parameters themselves
are sealed, so reviewers can read what they approve while the table holds no plaintext.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
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

from agentguard.core.db import Base, OrgScoped, new_id

# pending: waiting for reviewers. approved: may run (once). rejected, changes_requested,
# expired, revoked: final, cannot run. executed / failed: AgentGuard ran it, or the agent
# redeemed it.
STATUSES = (
    "pending",
    "approved",
    "rejected",
    "changes_requested",
    "expired",
    "revoked",
    "executed",
    "failed",
)
FINAL = ("rejected", "changes_requested", "expired", "revoked", "executed", "failed")
VOTES = ("approve", "reject", "request_changes")


class ApprovalRequest(OrgScoped, Base):
    __tablename__ = "approval_requests"
    __table_args__ = (
        Index("ix_approvals_org_status", "org_id", "status", "created_at"),
        Index("ix_approvals_hash", "org_id", "action_hash"),
    )
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    decision_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("decisions.id", ondelete="SET NULL")
    )
    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False
    )
    run_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("runs.id", ondelete="SET NULL")
    )
    tool: Mapped[str] = mapped_column(String(200), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    resource: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    action_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    # Canonical parameters, sealed with the record id as context.
    params_sealed: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    # Redacted parameters for lists and for auditors.
    params_preview: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    # Why it needs a person, from the deciding policy rule.
    reason: Mapped[str] = mapped_column(String(1000), nullable=False, default="")
    policy_name: Mapped[str | None] = mapped_column(String(120))
    policy_version: Mapped[int | None] = mapped_column(Integer)
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    # {"stages": [{"roles": [...], "users": [...], "count": n}], "execute": "agentguard"|"agent"}
    requirement: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    current_stage: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    on_behalf_of: Mapped[str | None] = mapped_column(String(320))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    decided_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    decision_comment: Mapped[str | None] = mapped_column(String(2000))
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    execution_decision_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    # The tool's result when AgentGuard executed it (redacted, bounded).
    result: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)


class ApprovalVote(OrgScoped, Base):
    __tablename__ = "approval_votes"
    __table_args__ = (
        UniqueConstraint("request_id", "stage", "user_id", name="uq_approval_votes_once"),
    )
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    request_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("approval_requests.id", ondelete="CASCADE"), nullable=False
    )
    stage: Mapped[int] = mapped_column(Integer, nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    vote: Mapped[str] = mapped_column(String(20), nullable=False)
    comment: Mapped[str] = mapped_column(String(2000), nullable=False, default="")
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class ApprovalHistory(OrgScoped, Base):
    """Append-only (a trigger refuses UPDATE and DELETE)."""

    __tablename__ = "approval_history"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    request_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("approval_requests.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    event: Mapped[str] = mapped_column(String(32), nullable=False)
    actor: Mapped[str] = mapped_column(String(320), nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
