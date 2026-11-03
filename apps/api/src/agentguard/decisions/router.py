"""The agent runtime API (authorize, execute, scan, redeem, runs, approval status) and the
decision log for the dashboard.

Fail closed: if AgentGuard cannot reach its database while deciding, ``authorize`` and
``execute`` answer 503 with ``decision: deny`` and ``reason_code: guard_unavailable``, and
the SDKs treat any error as a denial.
"""

from __future__ import annotations

import asyncio
import contextlib
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from redis.exceptions import RedisError
from sqlalchemy import select, tuple_, update
from sqlalchemy.exc import DBAPIError, OperationalError

from agentguard.approvals import service as approvals
from agentguard.auth.dependencies import StaffRead
from agentguard.core.deps import ContainerDep, SessionDep, client_ip
from agentguard.core.errors import NotFoundError
from agentguard.core.schemas import Page, decode_cursor, encode_cursor
from agentguard.decisions import service
from agentguard.decisions.models import Decision, Run
from agentguard.decisions.schemas import (
    AuthorizeRequest,
    AuthorizeResponse,
    DecisionDetail,
    DecisionOut,
    ExecuteResponse,
    RedeemRequest,
    RedeemResponse,
    RunOut,
    ScanRequest,
    ScanResponse,
)
from agentguard.identity.dependencies import AgentAuth
from agentguard.identity.models import Agent

router = APIRouter(tags=["agent runtime"])
log_router = APIRouter(prefix="/api/v1", tags=["decisions"])

_UNAVAILABLE = (OperationalError, DBAPIError, RedisError, OSError, ConnectionError, TimeoutError)


def _closed(exc: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={
            "decision": "deny",
            "allowed": False,
            "reason_code": "guard_unavailable",
            "reason": "AgentGuard could not decide right now, so the action is denied",
            "error": {
                "code": "guard_unavailable",
                "type": "service_unavailable",
                "message": type(exc).__name__,
                "details": {},
            },
        },
    )


@router.post(
    "/api/v1/authorize",
    response_model=AuthorizeResponse,
    summary="Decide one action (the agent then runs it, or asks a person)",
)
async def authorize(
    body: AuthorizeRequest,
    principal: AgentAuth,
    request: Request,
    container: ContainerDep,
    session: SessionDep,
) -> Any:
    try:
        return await service.authorize(container, session, principal, body, ip=client_ip(request))
    except _UNAVAILABLE as exc:
        return _closed(exc)


@router.post(
    "/api/v1/execute",
    response_model=ExecuteResponse,
    summary="Decide one action and, when allowed, run it through AgentGuard",
)
async def execute(
    body: AuthorizeRequest,
    principal: AgentAuth,
    request: Request,
    container: ContainerDep,
    session: SessionDep,
) -> Any:
    try:
        return await service.execute(container, session, principal, body, ip=client_ip(request))
    except _UNAVAILABLE as exc:
        return _closed(exc)


@router.post(
    "/api/v1/content/scan",
    response_model=ScanResponse,
    summary="Scan untrusted content the agent read (taints the run on injection)",
)
async def scan(
    body: ScanRequest, principal: AgentAuth, container: ContainerDep, session: SessionDep
) -> ScanResponse:
    return await service.scan(container, session, principal, body)


@router.post(
    "/api/v1/decisions/redeem",
    response_model=RedeemResponse,
    summary="Verify and use up a decision token (called by the tool about to act)",
)
async def redeem(
    body: RedeemRequest, actor: StaffRead, container: ContainerDep, session: SessionDep
) -> RedeemResponse:
    return await service.redeem(container, session, actor.org_id, body.token, body.action_hash)


class RunEnd(BaseModel):
    ended: bool = True


@router.post(
    "/api/v1/runs/{run_key}/end",
    response_model=RunEnd,
    summary="Mark the agent's run finished (frees a concurrent-run slot)",
)
async def end_run(run_key: str, principal: AgentAuth, session: SessionDep) -> RunEnd:
    result = await session.execute(
        update(Run)
        .where(Run.agent_id == principal.agent.id, Run.run_key == run_key, Run.ended_at.is_(None))
        .values(ended_at=datetime.now(UTC))
        .returning(Run.id)
    )
    found = result.scalar() is not None
    await session.commit()
    return RunEnd(ended=found)


class ApprovalStatus(BaseModel):
    id: uuid.UUID
    status: str
    comment: str | None
    expires_at: datetime
    decided_at: datetime | None
    result: dict[str, Any] | None = None


@router.get(
    "/api/v1/approvals/{approval_id}/status",
    response_model=ApprovalStatus,
    summary="Wait for a decision on the agent's own approval request",
)
async def approval_status(
    approval_id: uuid.UUID,
    principal: AgentAuth,
    container: ContainerDep,
    session: SessionDep,
    wait: int = Query(0, ge=0, le=30, description="Long-poll up to this many seconds for a change"),
) -> ApprovalStatus:
    request = await approvals.get(session, principal.org_id, approval_id)
    if request.agent_id != principal.agent.id:
        raise NotFoundError("Approval not found")
    deadline = asyncio.get_running_loop().time() + wait
    while request.status == "pending" and asyncio.get_running_loop().time() < deadline:
        await asyncio.sleep(0.5)
        await session.refresh(request)
    return ApprovalStatus(
        id=request.id,
        status=request.status,
        comment=request.decision_comment,
        expires_at=request.expires_at,
        decided_at=request.decided_at,
        result=request.result or None,
    )


def _out(row: Decision, agents: dict[uuid.UUID, str]) -> DecisionOut:
    return DecisionOut(
        id=row.id,
        at=row.at,
        agent_id=row.agent_id,
        agent=agents.get(row.agent_id) if row.agent_id else None,
        run_id=row.run_id,
        source=row.source,
        tool=row.tool,
        action=row.action,
        resource=row.resource,
        decision=row.decision,
        would_be=row.would_be,
        mode=row.mode,
        reason_code=row.reason_code,
        reasons=row.reasons,
        policy_id=row.policy_id,
        policy_name=row.policy_name,
        policy_version=row.policy_version,
        risk_level=row.risk_level,
        risk_score=row.risk_score,
        data_classes=row.data_classes,
        obligations=row.obligations,
        approval_id=row.approval_id,
        latency_ms=row.latency_ms,
        execution=row.execution,
        on_behalf_of=row.on_behalf_of,
    )


async def _agent_names(session: SessionDep, ids: set[uuid.UUID]) -> dict[uuid.UUID, str]:
    if not ids:
        return {}
    return dict(
        (await session.execute(select(Agent.id, Agent.slug).where(Agent.id.in_(ids)))).all()
    )


@log_router.get(
    "/access/decisions", response_model=Page[DecisionOut], summary="The decision log, newest first"
)
async def list_decisions(
    actor: StaffRead,
    session: SessionDep,
    agent_id: uuid.UUID | None = None,
    decision: str | None = Query(
        None, pattern="^(allow|deny|require_approval|restrict|quarantine)$"
    ),
    tool: str | None = Query(None, max_length=200),
    reason_code: str | None = Query(None, max_length=48),
    risk: str | None = Query(None, pattern="^(low|medium|high|critical)$"),
    source: str | None = Query(None, max_length=16),
    hours: int = Query(24 * 30, ge=1, le=24 * 365),
    cursor: str | None = None,
    limit: int = Query(50, ge=1, le=200),
) -> Page[DecisionOut]:
    since = datetime.now(UTC) - timedelta(hours=hours)
    stmt = select(Decision).where(Decision.org_id == actor.org_id, Decision.at >= since)
    if agent_id:
        stmt = stmt.where(Decision.agent_id == agent_id)
    if decision:
        stmt = stmt.where(Decision.would_be == decision)
    if tool:
        stmt = stmt.where(Decision.tool == tool)
    if reason_code:
        stmt = stmt.where(Decision.reason_code == reason_code)
    if risk:
        stmt = stmt.where(Decision.risk_level == risk)
    if source:
        stmt = stmt.where(Decision.source == source)
    raw = decode_cursor(cursor)
    if raw:
        at_s, _, id_s = raw.partition("|")
        with contextlib.suppress(ValueError):
            stmt = stmt.where(
                tuple_(Decision.at, Decision.id)
                < tuple_(datetime.fromisoformat(at_s), uuid.UUID(id_s))
            )
    rows = list(
        (
            await session.scalars(
                stmt.order_by(Decision.at.desc(), Decision.id.desc()).limit(limit + 1)
            )
        ).all()
    )
    names = await _agent_names(session, {r.agent_id for r in rows if r.agent_id})
    page = rows[:limit]
    nxt = encode_cursor(f"{page[-1].at.isoformat()}|{page[-1].id}") if len(rows) > limit else None
    return Page(items=[_out(r, names) for r in page], next_cursor=nxt)


@log_router.get(
    "/decisions/{decision_id}",
    response_model=DecisionDetail,
    summary="One decision with its explanation",
)
async def get_decision(
    decision_id: uuid.UUID, actor: StaffRead, session: SessionDep
) -> DecisionDetail:
    row = await session.get(Decision, decision_id)
    if row is None or row.org_id != actor.org_id:
        raise NotFoundError("Decision not found")
    names = await _agent_names(session, {row.agent_id} if row.agent_id else set())
    return DecisionDetail(
        **_out(row, names).model_dump(),
        params=row.params,
        matched=row.matched,
        risk_factors=row.risk_factors,
        execution_meta=row.execution_meta,
        action_hash=row.action_hash,
    )


@log_router.get("/runs", response_model=list[RunOut], summary="Recent runs of agents")
async def list_runs(
    actor: StaffRead,
    session: SessionDep,
    agent_id: uuid.UUID | None = None,
    tainted: bool | None = None,
    limit: int = Query(100, ge=1, le=500),
) -> list[Run]:
    stmt = select(Run).where(Run.org_id == actor.org_id)
    if agent_id:
        stmt = stmt.where(Run.agent_id == agent_id)
    if tainted is not None:
        stmt = stmt.where(Run.tainted_at.is_not(None) if tainted else Run.tainted_at.is_(None))
    return list((await session.scalars(stmt.order_by(Run.last_at.desc()).limit(limit))).all())


@log_router.get(
    "/runs/{run_id}",
    response_model=list[DecisionOut],
    summary="Every decision of one run, in order",
)
async def run_decisions(
    run_id: uuid.UUID, actor: StaffRead, session: SessionDep
) -> list[DecisionOut]:
    run = await session.get(Run, run_id)
    if run is None or run.org_id != actor.org_id:
        raise NotFoundError("Run not found")
    rows = (
        await session.scalars(
            select(Decision).where(Decision.run_id == run.id).order_by(Decision.at).limit(1000)
        )
    ).all()
    names = await _agent_names(session, {run.agent_id})
    return [_out(r, names) for r in rows]
