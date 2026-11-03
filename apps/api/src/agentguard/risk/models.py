"""Organisation-specific risk rules."""

from __future__ import annotations

import uuid

from sqlalchemy import Boolean, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from agentguard.core.db import Base, OrgScoped, TimestampMixin, new_id


class RiskRule(OrgScoped, TimestampMixin, Base):
    """Points added to (or, when negative, taken from) the risk score when a condition holds."""

    __tablename__ = "risk_rules"
    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_risk_rules_org_name"),)
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    condition: Mapped[str] = mapped_column(String(1000), nullable=False)
    points: Mapped[int] = mapped_column(Integer, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
