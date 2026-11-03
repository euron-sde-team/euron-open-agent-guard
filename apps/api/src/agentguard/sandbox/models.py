"""Records of code run in the sandbox service."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Index, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from agentguard.core.db import Base, OrgScoped, new_id

# ok, nonzero_exit, timeout, memory, output_limit, killed, refused, error.
VERDICTS = ("ok", "nonzero_exit", "timeout", "memory", "output_limit", "killed", "refused", "error")


class SandboxSession(OrgScoped, Base):
    __tablename__ = "sandbox_sessions"
    __table_args__ = (Index("ix_sandbox_org_started", "org_id", "started_at"),)
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    agent_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), index=True)
    run_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    decision_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    tool: Mapped[str] = mapped_column(String(200), nullable=False)
    language: Mapped[str] = mapped_column(String(16), nullable=False)
    # none, or proxy (only the egress proxy is reachable, under the agent's network policy).
    network: Mapped[str] = mapped_column(String(8), nullable=False, default="none")
    limits: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    code_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    code_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    verdict: Mapped[str] = mapped_column(String(16), nullable=False, default="error")
    exit_code: Mapped[int | None] = mapped_column(Integer)
    signal: Mapped[int | None] = mapped_column(Integer)
    cpu_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    wall_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    memory_kb: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    stdout_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    stderr_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
