"""Network policies, the connection log, a destination tester, limits and the kill switch."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Query, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func, select, update

from agentguard.audit.service import audit
from agentguard.auth.dependencies import StaffRead, StaffWrite
from agentguard.core.deps import ContainerDep, SessionDep
from agentguard.core.errors import AppError, ConflictError, NotFoundError
from agentguard.core.events import commit
from agentguard.identity.models import Agent
from agentguard.limits.models import METRICS, ON_EXCEED, SCOPES, UsageLimit
from agentguard.network import service
from agentguard.network.models import EgressEvent, NetworkPolicy
from agentguard.org import service as org_service
from agentguard.org.schemas import KillSwitch, KillSwitchIn
from agentguard.policies.service import bump

router = APIRouter(prefix="/api/v1", tags=["network and limits"])


class NetworkPolicyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(..., min_length=2, max_length=120, pattern=r"^[a-z0-9][a-z0-9_.-]*$")
    description: str = Field("", max_length=500)
    rules: list[dict[str, Any]] = Field(default_factory=list, max_length=500)
    default_action: str = Field("deny", pattern="^(allow|deny)$")
    is_default: bool = False

    @field_validator("rules")
    @classmethod
    def _rules(cls, v: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            service.NetworkRule.model_validate(r).model_dump(exclude_defaults=True)
            | {"action": r["action"]}
            for r in v
        ]


class NetworkPolicyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    name: str
    description: str
    rules: list[dict[str, Any]]
    default_action: str
    is_default: bool
    created_at: datetime
    updated_at: datetime
    agents: int = 0
    blocked_24h: int = 0


class TestIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    host: str = Field(..., min_length=1, max_length=255)
    port: int = Field(443, ge=1, le=65535)
    method: str | None = Field(None, max_length=10)
    policy_id: uuid.UUID | None = None
    agent_id: uuid.UUID | None = None


class TestOut(BaseModel):
    allowed: bool
    reason: str
    policy: str | None
    rule: int | None
    addresses: list[str]


class EgressOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    at: datetime
    agent_id: uuid.UUID | None
    agent: str | None = None
    source: str
    host: str
    port: int
    ip: str | None
    method: str | None
    decision: str
    reason: str
    policy_name: str | None
    bytes_up: int
    bytes_down: int
    duration_ms: int


class LimitIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(..., min_length=1, max_length=120)
    scope_type: str = Field(..., pattern="^(" + "|".join(SCOPES) + ")$")
    scope_id: str | None = Field(None, max_length=320)
    metric: str = Field(..., pattern="^(" + "|".join(METRICS) + ")$")
    limit_value: int = Field(..., ge=0, le=10**15)
    window_s: int = Field(60, ge=1, le=30 * 86_400)
    on_exceed: str = Field("deny", pattern="^(" + "|".join(ON_EXCEED) + ")$")
    enabled: bool = True


class LimitOut(LimitIn):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    created_at: datetime


async def _policy(session: SessionDep, org_id: uuid.UUID, policy_id: uuid.UUID) -> NetworkPolicy:
    row = await session.get(NetworkPolicy, policy_id)
    if row is None or row.org_id != org_id:
        raise NotFoundError("Network policy not found")
    return row


async def _policies_out(
    session: SessionDep, org_id: uuid.UUID, rows: list[NetworkPolicy]
) -> list[NetworkPolicyOut]:
    agents = dict(
        (
            await session.execute(
                select(Agent.network_policy_id, func.count())
                .where(Agent.org_id == org_id)
                .group_by(Agent.network_policy_id)
            )
        ).all()
    )
    since = datetime.now(UTC) - timedelta(hours=24)
    blocked = dict(
        (
            await session.execute(
                select(EgressEvent.policy_name, func.count())
                .where(
                    EgressEvent.org_id == org_id,
                    EgressEvent.at >= since,
                    EgressEvent.decision == "deny",
                )
                .group_by(EgressEvent.policy_name)
            )
        ).all()
    )
    out = []
    for r in rows:
        item = NetworkPolicyOut.model_validate(r)
        item.agents = int(agents.get(r.id, 0)) + (int(agents.get(None, 0)) if r.is_default else 0)
        item.blocked_24h = int(blocked.get(r.name, 0))
        out.append(item)
    return out


@router.get("/network-policies", response_model=list[NetworkPolicyOut], summary="Network policies")
async def list_policies(actor: StaffRead, session: SessionDep) -> list[NetworkPolicyOut]:
    rows = (
        await session.scalars(
            select(NetworkPolicy)
            .where(NetworkPolicy.org_id == actor.org_id)
            .order_by(NetworkPolicy.name)
        )
    ).all()
    return await _policies_out(session, actor.org_id, list(rows))


async def _only_default(session: SessionDep, org_id: uuid.UUID, keep: uuid.UUID) -> None:
    await session.execute(
        update(NetworkPolicy)
        .where(NetworkPolicy.org_id == org_id, NetworkPolicy.id != keep)
        .values(is_default=False)
    )


@router.post(
    "/network-policies",
    response_model=NetworkPolicyOut,
    status_code=201,
    summary="Create a network policy",
)
async def create_policy(
    body: NetworkPolicyIn, actor: StaffWrite, session: SessionDep
) -> NetworkPolicyOut:
    if await session.scalar(
        select(NetworkPolicy.id).where(
            NetworkPolicy.org_id == actor.org_id, NetworkPolicy.name == body.name
        )
    ):
        raise ConflictError(f"A network policy named {body.name} exists", code="duplicate")
    row = NetworkPolicy(org_id=actor.org_id, **body.model_dump())
    session.add(row)
    await session.flush()
    if row.is_default:
        await _only_default(session, actor.org_id, row.id)
    audit(
        session,
        actor,
        "network_policy.created",
        "network_policy",
        row.id,
        name=row.name,
        rules=len(row.rules),
    )
    await session.commit()
    return (await _policies_out(session, actor.org_id, [row]))[0]


@router.put(
    "/network-policies/{policy_id}",
    response_model=NetworkPolicyOut,
    summary="Replace a network policy",
)
async def update_policy(
    policy_id: uuid.UUID, body: NetworkPolicyIn, actor: StaffWrite, session: SessionDep
) -> NetworkPolicyOut:
    row = await _policy(session, actor.org_id, policy_id)
    for key, value in body.model_dump().items():
        setattr(row, key, value)
    if row.is_default:
        await _only_default(session, actor.org_id, row.id)
    audit(session, actor, "network_policy.updated", "network_policy", row.id, rules=len(row.rules))
    await session.commit()
    return (await _policies_out(session, actor.org_id, [row]))[0]


@router.delete("/network-policies/{policy_id}", status_code=204, summary="Delete a network policy")
async def delete_policy(policy_id: uuid.UUID, actor: StaffWrite, session: SessionDep) -> Response:
    row = await _policy(session, actor.org_id, policy_id)
    if row.is_default:
        raise AppError("Make another policy the default first", code="is_default")
    audit(session, actor, "network_policy.deleted", "network_policy", row.id, name=row.name)
    await session.delete(row)
    await session.commit()
    return Response(status_code=204)


@router.post(
    "/network-policies/test", response_model=TestOut, summary="Would this destination be allowed?"
)
async def test_destination(
    body: TestIn, actor: StaffRead, container: ContainerDep, session: SessionDep
) -> TestOut:
    policy_id = body.policy_id
    if body.agent_id is not None:
        agent = await session.get(Agent, body.agent_id)
        if agent is None or agent.org_id != actor.org_id:
            raise NotFoundError("Agent not found")
        policy_id = agent.network_policy_id
    verdict, ips = await service.decide(
        session,
        actor.org_id,
        policy_id,
        host=body.host,
        port=body.port,
        method=body.method,
        allow_private=container.settings.allow_private_urls,
    )
    return TestOut(
        allowed=verdict.allowed,
        reason=verdict.reason,
        policy=verdict.policy,
        rule=verdict.rule,
        addresses=[str(i) for i in ips],
    )


@router.get(
    "/egress-events", response_model=list[EgressOut], summary="Outbound connections, newest first"
)
async def egress_events(
    actor: StaffRead,
    session: SessionDep,
    decision: str | None = Query(None, pattern="^(allow|deny)$"),
    agent_id: uuid.UUID | None = None,
    source: str | None = Query(None, max_length=16),
    limit: int = Query(200, ge=1, le=1000),
) -> list[EgressOut]:
    stmt = select(EgressEvent).where(EgressEvent.org_id == actor.org_id)
    if decision:
        stmt = stmt.where(EgressEvent.decision == decision)
    if agent_id:
        stmt = stmt.where(EgressEvent.agent_id == agent_id)
    if source:
        stmt = stmt.where(EgressEvent.source == source)
    rows = (await session.scalars(stmt.order_by(EgressEvent.id.desc()).limit(limit))).all()
    names = dict(
        (
            await session.execute(select(Agent.id, Agent.slug).where(Agent.org_id == actor.org_id))
        ).all()
    )
    out = []
    for r in rows:
        item = EgressOut.model_validate(r)
        item.agent = names.get(r.agent_id) if r.agent_id else None
        out.append(item)
    return out


@router.get("/limits", response_model=list[LimitOut], summary="Execution limits")
async def list_limits(actor: StaffRead, session: SessionDep) -> list[UsageLimit]:
    return list(
        (
            await session.scalars(
                select(UsageLimit)
                .where(UsageLimit.org_id == actor.org_id)
                .order_by(UsageLimit.name)
            )
        ).all()
    )


@router.post("/limits", response_model=LimitOut, status_code=201, summary="Add a limit")
async def create_limit(
    body: LimitIn, actor: StaffWrite, container: ContainerDep, session: SessionDep
) -> UsageLimit:
    row = UsageLimit(org_id=actor.org_id, **body.model_dump())
    session.add(row)
    await session.flush()
    await bump(container, actor.org_id)
    audit(
        session,
        actor,
        "limit.created",
        "limit",
        row.id,
        name=row.name,
        metric=row.metric,
        value=row.limit_value,
    )
    await session.commit()
    return row


@router.put("/limits/{limit_id}", response_model=LimitOut, summary="Change a limit")
async def update_limit(
    limit_id: uuid.UUID,
    body: LimitIn,
    actor: StaffWrite,
    container: ContainerDep,
    session: SessionDep,
) -> UsageLimit:
    row = await session.get(UsageLimit, limit_id)
    if row is None or row.org_id != actor.org_id:
        raise NotFoundError("Limit not found")
    for key, value in body.model_dump().items():
        setattr(row, key, value)
    await bump(container, actor.org_id)
    audit(
        session, actor, "limit.updated", "limit", row.id, value=row.limit_value, enabled=row.enabled
    )
    await session.commit()
    return row


@router.delete("/limits/{limit_id}", status_code=204, summary="Remove a limit")
async def delete_limit(
    limit_id: uuid.UUID, actor: StaffWrite, container: ContainerDep, session: SessionDep
) -> Response:
    row = await session.get(UsageLimit, limit_id)
    if row is None or row.org_id != actor.org_id:
        raise NotFoundError("Limit not found")
    await bump(container, actor.org_id)
    audit(session, actor, "limit.deleted", "limit", row.id, name=row.name)
    await session.delete(row)
    await session.commit()
    return Response(status_code=204)


@router.put(
    "/kill-switch",
    response_model=KillSwitch,
    summary="Stop every agent of the organisation at once (or resume)",
)
async def kill_switch(
    body: KillSwitchIn, actor: StaffWrite, container: ContainerDep, session: SessionDep
) -> KillSwitch:
    switch = await org_service.set_kill_switch(session, actor, body.active, body.reason)
    await commit(container, session)
    return switch
