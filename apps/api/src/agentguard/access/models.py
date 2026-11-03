"""Roles and permissions for agents, and the resources agents act on.

Permissions grant; policies decide. A permission says an agent may perform some actions of
some tools on some resources. Roles are bound to the whole organisation, to a project (every
agent in it) or to one agent, so an agent inherits what its organisation and project grant
plus its own roles. Policies then refine the outcome (approval, restriction, denial), and an
explicit deny in any policy beats every grant.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from agentguard.core.db import Base, OrgScoped, TimestampMixin, new_id

SENSITIVITIES = ("public", "internal", "confidential", "restricted")
BINDING_SUBJECTS = ("org", "project", "agent")


class AgentRole(OrgScoped, TimestampMixin, Base):
    __tablename__ = "agent_roles"
    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_agent_roles_org_name"),)
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    # Names of roles whose permissions this one includes (no cycles; checked on save).
    inherits: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)


class Permission(OrgScoped, TimestampMixin, Base):
    __tablename__ = "permissions"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    role_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("agent_roles.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # Glob patterns: "crm.*", "customer_db"; "*" for any.
    tool: Mapped[str] = mapped_column(String(200), nullable=False)
    actions: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    # Glob on the resource key ("customer:*", "database:staging"); "*" for any.
    resource: Mapped[str] = mapped_column(String(300), nullable=False, default="*")
    # Optional condition in the policy expression language ("params.amount <= 500").
    condition: Mapped[str] = mapped_column(String(1000), nullable=False, default="")


class RoleBinding(OrgScoped, TimestampMixin, Base):
    __tablename__ = "role_bindings"
    __table_args__ = (
        UniqueConstraint(
            "role_id", "subject_type", "subject_id", name="uq_role_bindings_role_subject"
        ),
        Index("ix_role_bindings_subject", "org_id", "subject_type", "subject_id"),
    )
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    role_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agent_roles.id", ondelete="CASCADE"), nullable=False
    )
    subject_type: Mapped[str] = mapped_column(String(16), nullable=False)
    # The organisation, project or agent id.
    subject_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)


class Resource(OrgScoped, TimestampMixin, Base):
    """Something agents act on whose sensitivity and owner matter to decisions.

    Resources are optional: an action on an unregistered key is decided by policy alone
    (resource.registered is false), so teams can start with tools and add resources later.
    """

    __tablename__ = "resources"
    __table_args__ = (UniqueConstraint("org_id", "key", name="uq_resources_org_key"),)
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    # The project that owns it. Agents of other projects need an explicit grant.
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id", ondelete="SET NULL"), index=True
    )
    # "<type>:<id>" or a pattern ("database:production", "customer:*").
    key: Mapped[str] = mapped_column(String(300), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    type: Mapped[str] = mapped_column(String(64), nullable=False)
    sensitivity: Mapped[str] = mapped_column(String(16), nullable=False, default="internal")
    environment: Mapped[str] = mapped_column(String(16), nullable=False, default="production")
    # Classes of data it holds (pii, financial, health, credentials, source_code).
    data_classes: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    tags: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
