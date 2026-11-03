"""Policies: write, version, validate, evaluate, simulate, activate, roll back."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select

from agentguard.auth.dependencies import StaffRead, StaffWrite
from agentguard.core.deps import ContainerDep, SessionDep
from agentguard.decisions.schemas import EvaluateRequest, EvaluateResponse
from agentguard.policies import service
from agentguard.policies.dsl import PolicyError, compile_policy
from agentguard.policies.models import Policy, PolicyVersion

router = APIRouter(prefix="/api/v1/policies", tags=["policies"])


class PolicyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: str = Field(..., min_length=10, max_length=200_000, description="The policy in YAML")
    activate: bool = True
    comment: str = Field("", max_length=500)


class VersionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    version: int
    source: str
    comment: str
    created_at: datetime
    created_by: uuid.UUID | None


class PolicyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    name: str
    description: str
    status: str
    builtin: bool
    active_version: int | None
    latest_version: int
    created_at: datetime
    updated_at: datetime
    rules: int = 0
    decisions: list[str] = Field(default_factory=list)


class PolicyDetail(PolicyOut):
    source: str
    compiled: dict[str, Any]
    versions: list[VersionOut]


class ValidateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: str = Field(..., max_length=200_000)


class ValidateOut(BaseModel):
    valid: bool
    error: str | None = None
    compiled: dict[str, Any] | None = None


class SimulateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: str = Field(..., max_length=200_000)
    policy_id: uuid.UUID | None = Field(None, description="The policy this draft would replace")
    days: int = Field(7, ge=1, le=90)


class SimulateOut(BaseModel):
    evaluated: int
    changed: list[dict[str, Any]]
    summary: dict[str, dict[str, int]]


class ActivateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: int = Field(..., ge=1)


async def _active_source(session: SessionDep, policy: Policy) -> PolicyVersion:
    version = policy.active_version or policy.latest_version
    return await service.version_of(session, policy, version)


def _summary(policy: Policy, compiled: dict[str, Any]) -> PolicyOut:
    out = PolicyOut.model_validate(policy)
    out.rules = len(compiled.get("rules", []))
    out.decisions = sorted({r["decision"] for r in compiled.get("rules", [])})
    return out


@router.get("", response_model=list[PolicyOut], summary="Policies with their active version")
async def list_policies(actor: StaffRead, session: SessionDep) -> list[PolicyOut]:
    rows = (
        await session.execute(
            select(Policy, PolicyVersion)
            .join(
                PolicyVersion,
                (PolicyVersion.policy_id == Policy.id)
                & (
                    PolicyVersion.version
                    == func.coalesce(Policy.active_version, Policy.latest_version)
                ),
            )
            .where(Policy.org_id == actor.org_id)
            .order_by(Policy.builtin, Policy.name)
        )
    ).all()
    return [_summary(p, v.compiled) for p, v in rows]


@router.post("", response_model=PolicyDetail, status_code=201, summary="Create a policy from YAML")
async def create(
    body: PolicyIn, actor: StaffWrite, container: ContainerDep, session: SessionDep
) -> PolicyDetail:
    policy, _ = await service.create(
        container, session, actor, body.source, activate=body.activate, comment=body.comment
    )
    await session.commit()
    return await get_policy(policy.id, actor, session)


@router.post(
    "/validate", response_model=ValidateOut, summary="Check a policy document without saving it"
)
async def validate(body: ValidateIn, actor: StaffRead) -> ValidateOut:
    try:
        return ValidateOut(valid=True, compiled=compile_policy(body.source))
    except PolicyError as exc:
        return ValidateOut(valid=False, error=str(exc))


@router.post(
    "/evaluate",
    response_model=EvaluateResponse,
    summary="Dry run: what would happen if this agent did this (nothing is recorded)",
)
async def evaluate(
    body: EvaluateRequest, actor: StaffRead, container: ContainerDep, session: SessionDep
) -> EvaluateResponse:
    from agentguard.decisions.preview import preview

    return await preview(container, session, actor.org_id, body)


@router.post(
    "/simulate",
    response_model=SimulateOut,
    summary="Re-decide recorded decisions with a draft and list what changes",
)
async def simulate(
    body: SimulateIn, actor: StaffRead, container: ContainerDep, session: SessionDep
) -> SimulateOut:
    if body.policy_id is not None:
        await service.get(session, actor.org_id, body.policy_id)
    result = await service.simulate(
        container,
        session,
        actor.org_id,
        source=body.source,
        replace_policy_id=body.policy_id,
        days=body.days,
    )
    return SimulateOut(evaluated=result.evaluated, changed=result.changed, summary=result.summary)


@router.get("/{policy_id}", response_model=PolicyDetail, summary="One policy with every version")
async def get_policy(policy_id: uuid.UUID, actor: StaffRead, session: SessionDep) -> PolicyDetail:
    policy = await service.get(session, actor.org_id, policy_id)
    current = await _active_source(session, policy)
    versions = (
        await session.scalars(
            select(PolicyVersion)
            .where(PolicyVersion.policy_id == policy.id)
            .order_by(PolicyVersion.version.desc())
        )
    ).all()
    base = _summary(policy, current.compiled)
    return PolicyDetail(
        **base.model_dump(),
        source=current.source,
        compiled=current.compiled,
        versions=[VersionOut.model_validate(v) for v in versions],
    )


@router.put(
    "/{policy_id}",
    response_model=PolicyDetail,
    summary="Save a new version (activated unless activate is false)",
)
async def update(
    policy_id: uuid.UUID,
    body: PolicyIn,
    actor: StaffWrite,
    container: ContainerDep,
    session: SessionDep,
) -> PolicyDetail:
    policy = await service.get(session, actor.org_id, policy_id)
    await service.save_version(
        container, session, actor, policy, body.source, activate=body.activate, comment=body.comment
    )
    await session.commit()
    return await get_policy(policy.id, actor, session)


@router.post(
    "/{policy_id}/activate", response_model=PolicyDetail, summary="Make a version the active one"
)
async def activate(
    policy_id: uuid.UUID,
    body: ActivateIn,
    actor: StaffWrite,
    container: ContainerDep,
    session: SessionDep,
) -> PolicyDetail:
    policy = await service.get(session, actor.org_id, policy_id)
    await service.activate(container, session, actor, policy, body.version)
    await session.commit()
    return await get_policy(policy.id, actor, session)


@router.post(
    "/{policy_id}/rollback",
    response_model=PolicyDetail,
    summary="Activate the version before the active one",
)
async def rollback(
    policy_id: uuid.UUID, actor: StaffWrite, container: ContainerDep, session: SessionDep
) -> PolicyDetail:
    policy = await service.get(session, actor.org_id, policy_id)
    await service.rollback(container, session, actor, policy)
    await session.commit()
    return await get_policy(policy.id, actor, session)


@router.post(
    "/{policy_id}/disable",
    response_model=PolicyDetail,
    summary="Stop applying a policy (its versions are kept)",
)
async def disable(
    policy_id: uuid.UUID, actor: StaffWrite, container: ContainerDep, session: SessionDep
) -> PolicyDetail:
    policy = await service.get(session, actor.org_id, policy_id)
    await service.disable(container, session, actor, policy)
    await session.commit()
    return await get_policy(policy.id, actor, session)


@router.delete(
    "/{policy_id}",
    status_code=204,
    summary="Delete a policy and its history (built-in policies cannot be deleted)",
)
async def delete(
    policy_id: uuid.UUID, actor: StaffWrite, container: ContainerDep, session: SessionDep
) -> Response:
    policy = await service.get(session, actor.org_id, policy_id)
    await service.delete(container, session, actor, policy)
    await session.commit()
    return Response(status_code=204)
