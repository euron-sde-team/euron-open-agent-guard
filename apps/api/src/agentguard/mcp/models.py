"""The MCP server catalog and the history of every tool definition it has seen."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from agentguard.core.db import Base, OrgScoped, TimestampMixin, new_id

TRANSPORTS = ("http", "stdio")
# unknown (never checked), up, degraded (slow or one failure), down (three failures).
HEALTH = ("unknown", "up", "degraded", "down")


class McpServer(OrgScoped, TimestampMixin, Base):
    __tablename__ = "mcp_servers"
    __table_args__ = (UniqueConstraint("org_id", "slug", name="uq_mcp_servers_org_slug"),)
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id", ondelete="SET NULL")
    )
    # The namespace of its tools at the gateway: <slug>.<tool>.
    slug: Mapped[str] = mapped_column(String(48), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str] = mapped_column(String(1000), nullable=False, default="")
    transport: Mapped[str] = mapped_column(String(8), nullable=False)
    url: Mapped[str | None] = mapped_column(String(2000))
    command: Mapped[str | None] = mapped_column(String(500))
    args: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    # Header name (http) or environment variable (stdio) to managed secret name.
    secret_bindings: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    # Default risk and sensitivity for tools discovered on it.
    default_risk: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    # Bumped on any change to the URL, command, arguments or secret bindings: the pool then
    # replaces its connection on the next call.
    config_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    enabled: Mapped[bool] = mapped_column(nullable=False, default=True)
    health: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown")
    health_detail: Mapped[str | None] = mapped_column(String(500))
    consecutive_failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    server_info: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_discovered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class McpToolVersion(OrgScoped, Base):
    """One row per tool definition seen, so a silent change (a rug pull) is visible and dated."""

    __tablename__ = "mcp_tool_versions"
    __table_args__ = (
        Index("ix_mcp_tool_versions_server_tool", "server_id", "tool_name", "seen_at"),
    )
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    server_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("mcp_servers.id", ondelete="CASCADE"), nullable=False
    )
    tool_name: Mapped[str] = mapped_column(String(200), nullable=False)
    # sha256 over name, description, input and output schema and annotations.
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    definition: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    # added, changed, removed.
    change: Mapped[str] = mapped_column(String(16), nullable=False)
    seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    reviewed_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
