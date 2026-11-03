"""Managed secrets. Values go in; they never come back out."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select

from agentguard.audit.service import audit
from agentguard.auth.dependencies import StaffRead, StaffWrite
from agentguard.core.deps import ContainerDep, SessionDep
from agentguard.core.errors import NotFoundError
from agentguard.decisions.outputs import forget_secrets
from agentguard.identity.models import Agent
from agentguard.secrets import service
from agentguard.secrets.models import STORES, Secret, SecretAccess, SecretLease, SecretVersion

router = APIRouter(prefix="/api/v1/secrets", tags=["secrets"])


class SecretIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(..., min_length=2, max_length=120, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    value: str | None = Field(
        None, max_length=64_000, description="Write-only. Omit for env secrets"
    )
    store: str = Field("database", pattern="^(" + "|".join(STORES) + ")$")
    external_ref: str | None = Field(None, max_length=500)
    description: str = Field("", max_length=500)
    project_id: uuid.UUID | None = None
    expires_at: datetime | None = None
    rotation_days: int | None = Field(None, ge=1, le=3650)
    requires_lease: bool = False
    allowed_hosts: list[str] = Field(default_factory=list, max_length=50)


class SecretUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    description: str | None = Field(None, max_length=500)
    expires_at: datetime | None = None
    rotation_days: int | None = Field(None, ge=1, le=3650)
    requires_lease: bool | None = None
    allowed_hosts: list[str] | None = None


class RotateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    value: str = Field(..., min_length=1, max_length=64_000)
    grace_s: int = Field(
        3600, ge=0, le=7 * 86_400, description="How long the previous version keeps working"
    )


class RevokeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field("", max_length=500)


class LeaseIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: uuid.UUID
    minutes: int = Field(60, ge=1, le=7 * 24 * 60)
    max_uses: int | None = Field(None, ge=1, le=1_000_000)
    reason: str = Field("", max_length=500)


class LeaseOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    agent_id: uuid.UUID
    agent: str = ""
    expires_at: datetime
    max_uses: int | None
    uses: int
    revoked_at: datetime | None
    reason: str
    created_at: datetime


class VersionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    version: int
    hint: str
    external_version: str | None
    created_at: datetime


class AccessOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    at: datetime
    version: int
    agent_id: uuid.UUID | None
    decision_id: uuid.UUID | None
    purpose: str
    outcome: str
    detail: dict[str, Any]


class SecretOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    name: str
    description: str
    store: str
    external_ref: str | None
    project_id: uuid.UUID | None
    current_version: int
    previous_valid_until: datetime | None
    expires_at: datetime | None
    rotation_days: int | None
    rotated_at: datetime | None
    requires_lease: bool
    allowed_hosts: list[str]
    revoked_at: datetime | None
    last_used_at: datetime | None
    hint: str
    created_at: datetime
    status: str = "active"
    uses_24h: int = 0
    rotation_due: bool = False


class SecretDetail(SecretOut):
    versions: list[VersionOut]
    leases: list[LeaseOut]
    recent_access: list[AccessOut]


def _status(s: Secret) -> tuple[str, bool]:
    now = datetime.now(UTC)
    if s.revoked_at is not None:
        return "revoked", False
    if s.expires_at is not None and s.expires_at <= now:
        return "expired", False
    due = bool(
        s.rotation_days and s.rotated_at and s.rotated_at + timedelta(days=s.rotation_days) <= now
    )
    if s.expires_at is not None and s.expires_at <= now + timedelta(days=7):
        return "expiring", due
    return "active", due


async def _out(session: SessionDep, rows: list[Secret]) -> list[SecretOut]:
    since = datetime.now(UTC) - timedelta(hours=24)
    uses = (
        dict(
            (
                await session.execute(
                    select(SecretAccess.secret_id, func.count())
                    .where(
                        SecretAccess.secret_id.in_([s.id for s in rows]),
                        SecretAccess.at >= since,
                        SecretAccess.outcome == "used",
                    )
                    .group_by(SecretAccess.secret_id)
                )
            ).all()
        )
        if rows
        else {}
    )
    out = []
    for s in rows:
        item = SecretOut.model_validate(s)
        item.status, item.rotation_due = _status(s)
        item.uses_24h = int(uses.get(s.id, 0))
        out.append(item)
    return out


@router.get("", response_model=list[SecretOut], summary="Secrets (metadata only)")
async def list_secrets(actor: StaffRead, session: SessionDep) -> list[SecretOut]:
    rows = (
        await session.scalars(
            select(Secret).where(Secret.org_id == actor.org_id).order_by(Secret.name)
        )
    ).all()
    return await _out(session, list(rows))


@router.post(
    "",
    response_model=SecretOut,
    status_code=201,
    summary="Store a secret (the value is never returned)",
)
async def create(
    body: SecretIn, actor: StaffWrite, container: ContainerDep, session: SessionDep
) -> SecretOut:
    secret = await service.create_secret(container, session, actor, **body.model_dump())
    await session.commit()
    forget_secrets(actor.org_id)
    return (await _out(session, [secret]))[0]


@router.get(
    "/{secret_id}",
    response_model=SecretDetail,
    summary="One secret: versions, leases and recent use",
)
async def get(secret_id: uuid.UUID, actor: StaffRead, session: SessionDep) -> SecretDetail:
    secret = await service.get_secret(session, actor.org_id, secret_id)
    versions = (
        await session.scalars(
            select(SecretVersion)
            .where(SecretVersion.secret_id == secret.id)
            .order_by(SecretVersion.version.desc())
        )
    ).all()
    leases = (
        await session.scalars(
            select(SecretLease)
            .where(SecretLease.secret_id == secret.id)
            .order_by(SecretLease.created_at.desc())
            .limit(50)
        )
    ).all()
    access = (
        await session.scalars(
            select(SecretAccess)
            .where(SecretAccess.secret_id == secret.id)
            .order_by(SecretAccess.id.desc())
            .limit(50)
        )
    ).all()
    names = dict(
        (
            await session.execute(select(Agent.id, Agent.slug).where(Agent.org_id == actor.org_id))
        ).all()
    )
    base = (await _out(session, [secret]))[0]
    lease_out = []
    for lease in leases:
        item = LeaseOut.model_validate(lease)
        item.agent = names.get(lease.agent_id, "")
        lease_out.append(item)
    return SecretDetail(
        **base.model_dump(),
        versions=[VersionOut.model_validate(v) for v in versions],
        leases=lease_out,
        recent_access=[AccessOut.model_validate(a) for a in access],
    )


@router.patch("/{secret_id}", response_model=SecretOut, summary="Change a secret's metadata")
async def update(
    secret_id: uuid.UUID, body: SecretUpdate, actor: StaffWrite, session: SessionDep
) -> SecretOut:
    secret = await service.get_secret(session, actor.org_id, secret_id)
    changes = body.model_dump(exclude_unset=True)
    if "allowed_hosts" in changes and changes["allowed_hosts"] is not None:
        changes["allowed_hosts"] = [h.lower() for h in changes["allowed_hosts"]]
    for key, value in changes.items():
        setattr(secret, key, value)
    audit(session, actor, "secret.updated", "secret", secret.id, fields=sorted(changes))
    await session.commit()
    return (await _out(session, [secret]))[0]


@router.post(
    "/{secret_id}/rotate",
    response_model=SecretOut,
    summary="Write a new version (the previous one works for the grace period)",
)
async def rotate(
    secret_id: uuid.UUID,
    body: RotateIn,
    actor: StaffWrite,
    container: ContainerDep,
    session: SessionDep,
) -> SecretOut:
    secret = await service.get_secret(session, actor.org_id, secret_id)
    await service.rotate_secret(container, session, actor, secret, body.value, body.grace_s)
    await session.commit()
    forget_secrets(actor.org_id)
    return (await _out(session, [secret]))[0]


@router.post(
    "/{secret_id}/revoke", response_model=SecretOut, summary="Stop all use of a secret now"
)
async def revoke(
    secret_id: uuid.UUID, body: RevokeIn, actor: StaffWrite, session: SessionDep
) -> SecretOut:
    secret = await service.get_secret(session, actor.org_id, secret_id)
    await service.revoke_secret(session, actor, secret, body.reason)
    await session.commit()
    forget_secrets(actor.org_id)
    return (await _out(session, [secret]))[0]


@router.delete("/{secret_id}", status_code=204, summary="Delete a secret and its versions")
async def delete(secret_id: uuid.UUID, actor: StaffWrite, session: SessionDep) -> Response:
    secret = await service.get_secret(session, actor.org_id, secret_id)
    audit(session, actor, "secret.deleted", "secret", secret.id, name=secret.name)
    await session.delete(secret)
    await session.commit()
    forget_secrets(actor.org_id)
    return Response(status_code=204)


@router.post(
    "/{secret_id}/leases",
    response_model=LeaseOut,
    status_code=201,
    summary="Lend a secret to one agent for a while",
)
async def lease(
    secret_id: uuid.UUID, body: LeaseIn, actor: StaffWrite, session: SessionDep
) -> LeaseOut:
    secret = await service.get_secret(session, actor.org_id, secret_id)
    agent = await session.get(Agent, body.agent_id)
    if agent is None or agent.org_id != actor.org_id:
        raise NotFoundError("Agent not found")
    row = await service.grant_lease(
        session,
        actor,
        secret,
        agent.id,
        minutes=body.minutes,
        max_uses=body.max_uses,
        reason=body.reason,
    )
    await session.commit()
    out = LeaseOut.model_validate(row)
    out.agent = agent.slug
    return out


@router.delete("/{secret_id}/leases/{lease_id}", status_code=204, summary="End a lease now")
async def end_lease(
    secret_id: uuid.UUID, lease_id: uuid.UUID, actor: StaffWrite, session: SessionDep
) -> Response:
    lease = await session.get(SecretLease, lease_id)
    if lease is None or lease.org_id != actor.org_id or lease.secret_id != secret_id:
        raise NotFoundError("Lease not found")
    lease.revoked_at = lease.revoked_at or datetime.now(UTC)
    audit(session, actor, "secret.lease_revoked", "secret", secret_id, lease=str(lease_id))
    await session.commit()
    return Response(status_code=204)
