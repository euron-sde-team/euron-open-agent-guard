"""Security policies and their immutable versions.

A policy is a name with a history: every save writes a new version holding the YAML a
person wrote and the compiled form the engine evaluates. Exactly one version is active (or
none, for a draft or a disabled policy). Activation and rollback move the pointer and are
audited; versions are never edited, so every decision can name the exact rules that made it.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from agentguard.core.db import Base, OrgScoped, TimestampMixin, new_id

# draft (never active), active, disabled (was active, switched off).
STATUSES = ("draft", "active", "disabled")


class Policy(OrgScoped, TimestampMixin, Base):
    __tablename__ = "policies"
    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_policies_org_name"),)
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str] = mapped_column(String(1000), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="draft")
    # Built-in policies (the run taint guard) can be tuned and disabled, not deleted.
    builtin: Mapped[bool] = mapped_column(nullable=False, default=False)
    active_version: Mapped[int | None] = mapped_column(Integer)
    latest_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )


class PolicyVersion(OrgScoped, Base):
    __tablename__ = "policy_versions"
    __table_args__ = (UniqueConstraint("policy_id", "version", name="uq_policy_versions_version"),)
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    policy_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("policies.id", ondelete="CASCADE"), nullable=False
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    source: Mapped[str] = mapped_column(Text, nullable=False)
    compiled: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    comment: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
