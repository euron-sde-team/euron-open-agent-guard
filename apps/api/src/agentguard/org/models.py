"""Organisations, their projects and their security settings.

Settings edited as a unit (enforcement, kill switch, threat responses, detection, retention)
are JSONB documents validated by the Pydantic models in ``org.schemas`` on every write, so
the database never holds a shape the code cannot read.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import ForeignKey, Integer, LargeBinary, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from agentguard.core.db import Base, OrgScoped, TimestampMixin, new_id


class Org(TimestampMixin, Base):
    __tablename__ = "orgs"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    slug: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    # Incident numbers are per organisation (INC-1, INC-2): taken with UPDATE ... RETURNING.
    incident_seq: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class OrgSettings(TimestampMixin, Base):
    __tablename__ = "org_settings"
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("orgs.id", ondelete="CASCADE"), primary_key=True
    )
    # mode (enforce or audit), default decision, registered tools only, tokens on every allow.
    enforcement: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    # active, reason, by, at. When active every action of the organisation is denied.
    kill_switch: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    # Automatic responses per threat severity (quarantine, revoke, incident, notify).
    threat_responses: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    # Injection guard and AI-assisted detection (provider, model, thresholds).
    detection: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    # The provider key of AI-assisted detection, sealed; never returned by the API.
    ai_api_key_sealed: Mapped[bytes | None] = mapped_column(LargeBinary)
    # How long decision payloads and audit details are kept.
    retention: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    # Who is emailed about approvals, threats and incidents.
    notifications: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)


class Project(OrgScoped, TimestampMixin, Base):
    """A boundary inside an organisation: agents, tools, resources and secrets belong to one.

    An agent may act on resources of its own project; reaching another project's resources
    takes an explicit policy grant.
    """

    __tablename__ = "projects"
    __table_args__ = (UniqueConstraint("org_id", "slug", name="uq_projects_org_slug"),)
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    slug: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    # development, staging, production: available to policies as project.environment.
    environment: Mapped[str] = mapped_column(String(16), nullable=False, default="production")
