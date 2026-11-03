"""Agents and their credentials (dashboard and management API), the token exchange and JWKS
(public), and ``/agent/me`` (the agent itself)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Form, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select

from agentguard.access.models import AgentRole, RoleBinding
from agentguard.audit.service import audit
from agentguard.auth.dependencies import StaffRead, StaffWrite
from agentguard.core.deps import ContainerDep, SessionDep, client_ip
from agentguard.core.errors import AppError, ConflictError, NotFoundError, RateLimitedError
from agentguard.decisions.models import Decision
from agentguard.identity import service
from agentguard.identity.dependencies import AgentAuth
from agentguard.identity.models import Agent, AgentCredential
from agentguard.org.models import Project
from agentguard.threats.models import ThreatEvent

router = APIRouter(tags=["agents"])

FRAMEWORKS = (
    "langgraph",
    "crewai",
    "autogen",
    "mcp",
    "python",
    "node",
    "agentos",
    "service",
    "other",
)


class AgentIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    slug: str = Field(..., min_length=2, max_length=64, pattern=r"^[a-z0-9][a-z0-9-]*$")
    name: str = Field(..., min_length=1, max_length=120)
    description: str = Field("", max_length=1000)
    project_id: uuid.UUID | None = None
    framework: str = Field("other", pattern="^(" + "|".join(FRAMEWORKS) + ")$")
    labels: dict[str, str | int | bool] = Field(default_factory=dict)
    roles: list[str] = Field(default_factory=list, description="Agent roles bound to this agent")
    network_policy_id: uuid.UUID | None = None
    require_signed_requests: bool = False
    owner_user_id: uuid.UUID | None = None


class AgentUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(None, min_length=1, max_length=120)
    description: str | None = Field(None, max_length=1000)
    framework: str | None = Field(None, pattern="^(" + "|".join(FRAMEWORKS) + ")$")
    labels: dict[str, str | int | bool] | None = None
    roles: list[str] | None = None
    network_policy_id: uuid.UUID | None = None
    clear_network_policy: bool = False
    require_signed_requests: bool | None = None
    owner_user_id: uuid.UUID | None = None


class CredentialOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    client_id: str
    label: str
    created_at: datetime
    expires_at: datetime | None
    grace_until: datetime | None
    revoked_at: datetime | None
    last_used_at: datetime | None
    allowed_cidrs: list[str]


class IssuedOut(BaseModel):
    credential: CredentialOut
    client_id: str
    client_secret: str = Field(description="Shown once. Exchange it at /oauth/token")
    signing_secret: str = Field(description="Shown once. Signs requests when the agent requires it")
    token_url: str


class AgentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    slug: str
    name: str
    description: str
    project_id: uuid.UUID
    project: str = ""
    framework: str
    labels: dict[str, Any]
    status: str
    status_reason: str | None
    status_changed_at: datetime | None
    require_signed_requests: bool
    network_policy_id: uuid.UUID | None
    owner_user_id: uuid.UUID | None
    last_seen_at: datetime | None
    created_at: datetime
    roles: list[str] = Field(default_factory=list)
    decisions_24h: int = 0
    denied_24h: int = 0
    open_threats: int = 0


class AgentDetail(AgentOut):
    credentials: list[CredentialOut]
    pending_approvals: int = 0


class RegisteredOut(BaseModel):
    agent: AgentOut
    credential: IssuedOut


class StatusIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field("", max_length=500)


class CredentialIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    label: str = Field("default", max_length=80)
    expires_in_days: int | None = Field(None, ge=1, le=3650)
    allowed_cidrs: list[str] = Field(default_factory=list, max_length=20)


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "Bearer"  # noqa: S105 the OAuth token type
    expires_in: int
    agent: str
    agent_id: uuid.UUID


async def _role_ids(session: SessionDep, org_id: uuid.UUID, names: list[str]) -> list[uuid.UUID]:
    if not names:
        return []
    rows = (
        await session.execute(
            select(AgentRole.name, AgentRole.id).where(
                AgentRole.org_id == org_id, AgentRole.name.in_(names)
            )
        )
    ).all()
    found = dict(rows)
    missing = [n for n in names if n not in found]
    if missing:
        raise AppError(f"Unknown roles: {', '.join(missing)}", code="unknown_role")
    return [found[n] for n in names]


async def _set_roles(session: SessionDep, agent: Agent, names: list[str]) -> None:
    ids = await _role_ids(session, agent.org_id, names)
    existing = (
        await session.scalars(
            select(RoleBinding).where(
                RoleBinding.subject_type == "agent", RoleBinding.subject_id == agent.id
            )
        )
    ).all()
    for binding in existing:
        if binding.role_id not in ids:
            await session.delete(binding)
    have = {b.role_id for b in existing}
    for rid in ids:
        if rid not in have:
            session.add(
                RoleBinding(
                    org_id=agent.org_id, role_id=rid, subject_type="agent", subject_id=agent.id
                )
            )


async def _enrich(session: SessionDep, agents: list[Agent]) -> list[AgentOut]:
    if not agents:
        return []
    ids = [a.id for a in agents]
    since = datetime.now(UTC) - timedelta(hours=24)
    counts = {
        row[0]: (int(row[1]), int(row[2]))
        for row in (
            await session.execute(
                select(
                    Decision.agent_id,
                    func.count(),
                    func.count().filter(Decision.would_be.in_(("deny", "quarantine"))),
                )
                .where(Decision.agent_id.in_(ids), Decision.at >= since)
                .group_by(Decision.agent_id)
            )
        ).all()
    }
    threats = dict(
        (
            await session.execute(
                select(ThreatEvent.agent_id, func.count())
                .where(ThreatEvent.agent_id.in_(ids), ThreatEvent.status == "open")
                .group_by(ThreatEvent.agent_id)
            )
        ).all()
    )
    projects = dict(
        (
            await session.execute(
                select(Project.id, Project.slug).where(Project.org_id == agents[0].org_id)
            )
        ).all()
    )
    roles: dict[uuid.UUID, list[str]] = {}
    for agent_id, name in (
        await session.execute(
            select(RoleBinding.subject_id, AgentRole.name)
            .join(AgentRole, AgentRole.id == RoleBinding.role_id)
            .where(RoleBinding.subject_type == "agent", RoleBinding.subject_id.in_(ids))
        )
    ).all():
        roles.setdefault(agent_id, []).append(name)
    out = []
    for a in agents:
        item = AgentOut.model_validate(a)
        item.project = projects.get(a.project_id, "")
        item.decisions_24h, item.denied_24h = counts.get(a.id, (0, 0))
        item.open_threats = int(threats.get(a.id, 0))
        item.roles = sorted(roles.get(a.id, []))
        out.append(item)
    return out


def _issued(container: ContainerDep, issued: service.IssuedCredential) -> IssuedOut:
    return IssuedOut(
        credential=CredentialOut.model_validate(issued.credential),
        client_id=issued.client_id,
        client_secret=issued.client_secret,
        signing_secret=issued.signing_secret,
        token_url=f"{container.settings.public_api_url}/oauth/token",
    )


@router.post(
    "/api/v1/agents/register",
    response_model=RegisteredOut,
    status_code=201,
    summary="Register an agent and issue its first credential",
)
async def register(
    body: AgentIn, actor: StaffWrite, container: ContainerDep, session: SessionDep
) -> RegisteredOut:
    if await service.agent_by_slug(session, actor.org_id, body.slug):
        raise ConflictError(f"An agent named {body.slug} exists", code="duplicate")
    project_id = body.project_id
    if project_id is None:
        project_id = await session.scalar(
            select(Project.id)
            .where(Project.org_id == actor.org_id)
            .order_by(Project.created_at)
            .limit(1)
        )
    project = await session.get(Project, project_id) if project_id else None
    if project is None or project.org_id != actor.org_id:
        raise NotFoundError("Project not found")
    agent = Agent(
        org_id=actor.org_id,
        project_id=project.id,
        slug=body.slug,
        name=body.name,
        description=body.description,
        framework=body.framework,
        labels=body.labels,
        network_policy_id=body.network_policy_id,
        require_signed_requests=body.require_signed_requests,
        owner_user_id=body.owner_user_id or (actor.id if actor.kind == "user" else None),
    )
    session.add(agent)
    await session.flush()
    await _set_roles(session, agent, body.roles)
    audit(session, actor, "agent.registered", "agent", agent.id, slug=agent.slug, roles=body.roles)
    issued = await service.issue_credential(container, session, actor, agent)
    from agentguard.policies.service import bump

    await bump(container, actor.org_id)
    await session.commit()
    return RegisteredOut(
        agent=(await _enrich(session, [agent]))[0], credential=_issued(container, issued)
    )


@router.get(
    "/api/v1/agents", response_model=list[AgentOut], summary="Registered agents with their activity"
)
async def list_agents(
    actor: StaffRead,
    session: SessionDep,
    status: str | None = None,
    project_id: uuid.UUID | None = None,
    q: str | None = Query(None, max_length=100),
) -> list[AgentOut]:
    stmt = select(Agent).where(Agent.org_id == actor.org_id).order_by(Agent.name)
    if status:
        stmt = stmt.where(Agent.status == status)
    if project_id:
        stmt = stmt.where(Agent.project_id == project_id)
    if q:
        stmt = stmt.where(Agent.name.ilike(f"%{q}%") | Agent.slug.ilike(f"%{q}%"))
    return await _enrich(session, list((await session.scalars(stmt.limit(500))).all()))


@router.get(
    "/api/v1/agents/{agent_id}",
    response_model=AgentDetail,
    summary="One agent with its credentials",
)
async def get_agent(agent_id: uuid.UUID, actor: StaffRead, session: SessionDep) -> AgentDetail:
    from agentguard.approvals.models import ApprovalRequest

    agent = await service.get_agent(session, actor.org_id, agent_id)
    base = (await _enrich(session, [agent]))[0]
    creds = (
        await session.scalars(
            select(AgentCredential)
            .where(AgentCredential.agent_id == agent.id)
            .order_by(AgentCredential.created_at.desc())
        )
    ).all()
    pending = await session.scalar(
        select(func.count())
        .select_from(ApprovalRequest)
        .where(ApprovalRequest.agent_id == agent.id, ApprovalRequest.status == "pending")
    )
    return AgentDetail(
        **base.model_dump(),
        credentials=[CredentialOut.model_validate(c) for c in creds],
        pending_approvals=int(pending or 0),
    )


@router.patch("/api/v1/agents/{agent_id}", response_model=AgentOut, summary="Change an agent")
async def update_agent(
    agent_id: uuid.UUID,
    body: AgentUpdate,
    actor: StaffWrite,
    container: ContainerDep,
    session: SessionDep,
) -> AgentOut:
    agent = await service.get_agent(session, actor.org_id, agent_id)
    changes = body.model_dump(exclude_none=True, exclude={"roles", "clear_network_policy"})
    for key, value in changes.items():
        setattr(agent, key, value)
    if body.clear_network_policy:
        agent.network_policy_id = None
    if body.roles is not None:
        await _set_roles(session, agent, body.roles)
    audit(
        session,
        actor,
        "agent.updated",
        "agent",
        agent.id,
        fields=sorted([*changes, *(["roles"] if body.roles is not None else [])]),
    )
    from agentguard.policies.service import bump

    await bump(container, actor.org_id)
    await session.commit()
    return (await _enrich(session, [agent]))[0]


async def _status(
    agent_id: uuid.UUID,
    status: str,
    body: StatusIn,
    actor: StaffWrite,
    container: ContainerDep,
    session: SessionDep,
) -> AgentOut:
    from agentguard.core.events import commit

    agent = await service.get_agent(session, actor.org_id, agent_id)
    if status in ("suspended", "quarantined", "revoked") and not body.reason.strip():
        raise AppError("Say why", code="reason_required")
    await service.set_status(session, actor, agent, status, body.reason)
    await commit(container, session)
    return (await _enrich(session, [agent]))[0]


@router.post(
    "/api/v1/agents/{agent_id}/suspend",
    response_model=AgentOut,
    summary="Suspend an agent: every action is denied until reactivated",
)
async def suspend(
    agent_id: uuid.UUID,
    body: StatusIn,
    actor: StaffWrite,
    container: ContainerDep,
    session: SessionDep,
) -> AgentOut:
    return await _status(agent_id, "suspended", body, actor, container, session)


@router.post(
    "/api/v1/agents/{agent_id}/quarantine",
    response_model=AgentOut,
    summary="Quarantine an agent pending investigation",
)
async def quarantine(
    agent_id: uuid.UUID,
    body: StatusIn,
    actor: StaffWrite,
    container: ContainerDep,
    session: SessionDep,
) -> AgentOut:
    return await _status(agent_id, "quarantined", body, actor, container, session)


@router.post(
    "/api/v1/agents/{agent_id}/reactivate",
    response_model=AgentOut,
    summary="Let a suspended or quarantined agent act again",
)
async def reactivate(
    agent_id: uuid.UUID,
    body: StatusIn,
    actor: StaffWrite,
    container: ContainerDep,
    session: SessionDep,
) -> AgentOut:
    return await _status(agent_id, "active", body, actor, container, session)


@router.post(
    "/api/v1/agents/{agent_id}/revoke",
    response_model=AgentOut,
    summary="Retire an agent for good: credentials and tokens die at once",
)
async def revoke(
    agent_id: uuid.UUID,
    body: StatusIn,
    actor: StaffWrite,
    container: ContainerDep,
    session: SessionDep,
) -> AgentOut:
    return await _status(agent_id, "revoked", body, actor, container, session)


@router.post(
    "/api/v1/agents/{agent_id}/credentials",
    response_model=IssuedOut,
    status_code=201,
    summary="Issue another credential",
)
async def issue(
    agent_id: uuid.UUID,
    body: CredentialIn,
    actor: StaffWrite,
    container: ContainerDep,
    session: SessionDep,
) -> IssuedOut:
    agent = await service.get_agent(session, actor.org_id, agent_id)
    if agent.status == "revoked":
        raise AppError("A revoked agent cannot get credentials", code="revoked")
    issued = await service.issue_credential(
        container,
        session,
        actor,
        agent,
        label=body.label,
        expires_in_days=body.expires_in_days,
        allowed_cidrs=body.allowed_cidrs,
    )
    await session.commit()
    return _issued(container, issued)


async def _credential(
    session: SessionDep, org_id: uuid.UUID, agent_id: uuid.UUID, cred_id: uuid.UUID
) -> tuple[Agent, AgentCredential]:
    agent = await service.get_agent(session, org_id, agent_id)
    cred = await session.get(AgentCredential, cred_id)
    if cred is None or cred.agent_id != agent.id:
        raise NotFoundError("Credential not found")
    return agent, cred


@router.post(
    "/api/v1/agents/{agent_id}/credentials/{credential_id}/rotate",
    response_model=IssuedOut,
    status_code=201,
    summary="Rotate a credential (the old one works for the grace period)",
)
async def rotate(
    agent_id: uuid.UUID,
    credential_id: uuid.UUID,
    actor: StaffWrite,
    container: ContainerDep,
    session: SessionDep,
) -> IssuedOut:
    agent, cred = await _credential(session, actor.org_id, agent_id, credential_id)
    issued = await service.rotate_credential(container, session, actor, agent, cred)
    await session.commit()
    return _issued(container, issued)


@router.post(
    "/api/v1/agents/{agent_id}/credentials/{credential_id}/revoke",
    response_model=CredentialOut,
    summary="Revoke a credential now",
)
async def revoke_credential(
    agent_id: uuid.UUID, credential_id: uuid.UUID, actor: StaffWrite, session: SessionDep
) -> AgentCredential:
    _, cred = await _credential(session, actor.org_id, agent_id, credential_id)
    await service.revoke_credential(session, actor, cred)
    await session.commit()
    return cred


@router.post(
    "/oauth/token",
    response_model=TokenOut,
    tags=["agent runtime"],
    summary="Exchange client credentials for an access token (OAuth 2.0 client credentials)",
)
async def token(
    request: Request,
    container: ContainerDep,
    session: SessionDep,
    grant_type: Annotated[str, Form()],
    client_id: Annotated[str, Form(max_length=40)],
    client_secret: Annotated[str, Form(max_length=200)],
) -> TokenOut:
    ip = client_ip(request)
    decision = await container.kv.hit(f"token:{ip}", container.settings.token_rpm)
    if not decision.allowed:
        raise RateLimitedError(
            "Too many token requests from this address",
            headers={"retry-after": str(decision.retry_after_s)},
        )
    if grant_type != "client_credentials":
        raise AppError("grant_type must be client_credentials", code="unsupported_grant_type")
    access, ttl, agent = await service.exchange_token(
        container, session, client_id, client_secret, ip
    )
    return TokenOut(access_token=access, expires_in=ttl, agent=agent.slug, agent_id=agent.id)


@router.get(
    "/.well-known/jwks.json",
    tags=["agent runtime"],
    summary="Public keys that sign agent and decision tokens",
)
async def jwks(container: ContainerDep) -> dict[str, Any]:
    return await container.keys.jwks()


class MeOut(BaseModel):
    agent_id: uuid.UUID
    agent: str
    name: str
    org_id: uuid.UUID
    project: str
    status: str
    roles: list[str]


@router.get(
    "/api/v1/agent/me",
    response_model=MeOut,
    tags=["agent runtime"],
    summary="The calling agent's identity",
)
async def agent_me(principal: AgentAuth, container: ContainerDep, session: SessionDep) -> MeOut:
    from agentguard.access.resolve import for_agent

    agent = principal.agent
    project = await session.get(Project, agent.project_id)
    granted = await for_agent(container, session, agent.org_id, agent.project_id, agent.id)
    await session.commit()
    return MeOut(
        agent_id=agent.id,
        agent=agent.slug,
        name=agent.name,
        org_id=agent.org_id,
        project=project.slug if project else "",
        status=agent.status,
        roles=granted.roles,
    )
