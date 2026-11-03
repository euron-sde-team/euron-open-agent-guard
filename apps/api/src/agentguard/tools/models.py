"""The tool registry: every tool an agent may ask to use, and how AgentGuard runs it.

Kinds:

* ``http``: AgentGuard calls the tool's endpoint itself (secrets injected, network policy
  applied, response scanned). The agent never holds the credential.
* ``mcp``: a tool of a registered MCP server, called through the gateway.
* ``sandbox``: code run by the sandbox service.
* ``function``: runs inside the agent's own process or service; the tool verifies a
  single-use decision token before it acts.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import Boolean, ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from agentguard.core.db import Base, OrgScoped, TimestampMixin, new_id

KINDS = ("http", "mcp", "sandbox", "function")
RISK_LEVELS = ("low", "medium", "high", "critical")
# active: usable. disabled: refused. pending_review: changed upstream (MCP) and refused until
# a person reviews the change.
STATUSES = ("active", "disabled", "pending_review")


class Tool(OrgScoped, TimestampMixin, Base):
    __tablename__ = "tools"
    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_tools_org_name"),)
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id", ondelete="SET NULL"), index=True
    )
    # "customer_db", or "<server>.<tool>" for MCP tools.
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    description: Mapped[str] = mapped_column(String(2000), nullable=False, default="")
    # The verbs it supports (read, write, delete, send, execute...). Empty: "call".
    actions: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    # JSON schema of the parameters, validated before anything else.
    input_schema: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    # Per-parameter constraints: {"amount": {"max": 500}, "to": {"pattern": ".*@corp.example"}}.
    constraints: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    # How the resource key is built from the parameters: "customer:{customer_id}".
    resource_template: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    # Baseline risk of using it (the risk engine raises it from context).
    risk: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    # Sensitive tools fail closed whenever AgentGuard cannot decide.
    sensitive: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Sends data outside the organisation (email, webhooks, public APIs): DLP applies.
    external: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Kind-specific settings: http {method, url, headers, secret_headers, timeout_s};
    # mcp {server_id, upstream_name}; sandbox {language, timeout_s, memory_mb, network}.
    config: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")
    mcp_server_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("mcp_servers.id", ondelete="CASCADE"), index=True
    )
