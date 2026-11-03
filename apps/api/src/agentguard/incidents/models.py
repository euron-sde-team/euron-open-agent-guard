"""Security incidents, their timelines and evidence."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from agentguard.core.db import Base, OrgScoped, TimestampMixin, new_id

SEVERITIES = ("low", "medium", "high", "critical")
# open: investigating. contained: the threat is stopped (agent suspended, credentials
# revoked). resolved: closed with a root cause.
STATUSES = ("open", "contained", "resolved")


class Incident(OrgScoped, TimestampMixin, Base):
    __tablename__ = "incidents"
    __table_args__ = (Index("ix_incidents_org_status", "org_id", "status", "created_at"),)
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    # INC-<number>, per organisation.
    number: Mapped[int] = mapped_column(Integer, nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="open")
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    root_cause: Mapped[str] = mapped_column(Text, nullable=False, default="")
    resolution: Mapped[str] = mapped_column(Text, nullable=False, default="")
    agent_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    opened_by: Mapped[str] = mapped_column(String(320), nullable=False)
    assignee_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    contained_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class IncidentEvent(OrgScoped, Base):
    """One line of the timeline: a detection, a decision, a containment action, a note."""

    __tablename__ = "incident_events"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    actor: Mapped[str] = mapped_column(String(320), nullable=False)
    text: Mapped[str] = mapped_column(String(2000), nullable=False)
    ref_type: Mapped[str | None] = mapped_column(String(32))
    ref_id: Mapped[str | None] = mapped_column(String(64))


class IncidentEvidence(OrgScoped, Base):
    """A frozen copy of something relevant (a decision, a threat, audit records), hashed."""

    __tablename__ = "incident_evidence"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    ref_id: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    added_by: Mapped[str] = mapped_column(String(320), nullable=False)
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
