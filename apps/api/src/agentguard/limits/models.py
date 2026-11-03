"""Execution limits: how much an agent may do, per scope and metric."""

from __future__ import annotations

import uuid

from sqlalchemy import Boolean, Index, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from agentguard.core.db import Base, OrgScoped, TimestampMixin, new_id

SCOPES = ("org", "project", "agent", "user")
# tool_calls_per_run: calls in one run. run_duration_s: seconds since the run started.
# concurrent_runs: runs active at once. failed_attempts: denials in the window.
# requests_per_window: authorize calls in the window. data_transfer_bytes: bytes moved in
# the window (tool responses, egress). sandbox_memory_mb: the largest sandbox memory asked.
METRICS = (
    "tool_calls_per_run",
    "run_duration_s",
    "concurrent_runs",
    "failed_attempts",
    "requests_per_window",
    "data_transfer_bytes",
    "sandbox_memory_mb",
)
WINDOWED = ("failed_attempts", "requests_per_window", "data_transfer_bytes")
# deny: refuse the action. suspend: refuse it and suspend the agent.
ON_EXCEED = ("deny", "suspend")


class UsageLimit(OrgScoped, TimestampMixin, Base):
    __tablename__ = "usage_limits"
    __table_args__ = (Index("ix_usage_limits_scope", "org_id", "scope_type", "scope_id"),)
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    scope_type: Mapped[str] = mapped_column(String(16), nullable=False)
    # The project, agent or user; null applies to each one of that type separately
    # (scope_type agent with no id: every agent gets its own counter).
    scope_id: Mapped[str | None] = mapped_column(String(320))
    metric: Mapped[str] = mapped_column(String(32), nullable=False)
    limit_value: Mapped[int] = mapped_column(Integer, nullable=False)
    window_s: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    on_exceed: Mapped[str] = mapped_column(String(8), nullable=False, default="deny")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
