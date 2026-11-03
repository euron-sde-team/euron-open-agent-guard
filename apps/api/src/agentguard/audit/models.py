"""The tamper-evident audit log and its signed checkpoints.

Each record is written in the same transaction as the change it describes, unsealed. A
sealing task (one writer per organisation, under an advisory lock) then gives the committed records
their chain position in id order and links them:
``hash = sha256(prev_hash | seq | at | actor | action | target | details_digest)``. Writers
never contend for a per-organisation counter, so the decision hot path stays parallel. The
details are hashed separately (``details_digest``) so retention can drop old details while
the chain still verifies.

Database triggers (the initial migration) refuse every UPDATE except sealing an unsealed row and
pruning details, and refuse every DELETE. Signed checkpoints (Ed25519 over the head hash)
are exported to object storage, so rewriting the whole chain is caught too.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, Index, String, Text, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from agentguard.core.db import Base, OrgScoped


class AuditLog(OrgScoped, Base):
    __tablename__ = "audit_log"
    __table_args__ = (
        UniqueConstraint("org_id", "seq", name="uq_audit_log_org_seq"),
        Index("ix_audit_log_org_at", "org_id", "at"),
        Index("ix_audit_log_unsealed", "org_id", "id", postgresql_where=text("hash IS NULL")),
    )
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    # The chain position, gap-free per organisation; assigned when the record is sealed.
    seq: Mapped[int | None] = mapped_column(BigInteger)
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    # user, agent, api_key, system.
    actor_type: Mapped[str] = mapped_column(String(16), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(String(64))
    actor_name: Mapped[str | None] = mapped_column(String(320))
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    target_type: Mapped[str | None] = mapped_column(String(32))
    target_id: Mapped[str | None] = mapped_column(String(64))
    # Redacted. Null once retention pruned it; details_digest still proves what it was.
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    details_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    ip: Mapped[str | None] = mapped_column(String(64))
    prev_hash: Mapped[str | None] = mapped_column(String(64))
    hash: Mapped[str | None] = mapped_column(String(64))


class AuditHead(Base):
    """The head of each organisation's chain: the last sealed record."""

    __tablename__ = "audit_heads"
    org_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    sealed_seq: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    head_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="0" * 64)


class AuditCheckpoint(OrgScoped, Base):
    __tablename__ = "audit_checkpoints"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    head_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    kid: Mapped[str] = mapped_column(String(32), nullable=False)
    # base64url Ed25519 signature over "agentguard-audit|<org>|<seq>|<head_hash>|<at>".
    signature: Mapped[str] = mapped_column(Text, nullable=False)
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    storage_key: Mapped[str | None] = mapped_column(String(300))
