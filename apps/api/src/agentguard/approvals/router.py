"""Approval requests: the reviewer queue, votes, revocation, history."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select

from agentguard.approvals import service
from agentguard.approvals.models import ApprovalHistory, ApprovalRequest, ApprovalVote
from agentguard.auth.dependencies import ROLE_RANK, StaffRead, StaffReview, StaffWrite
from agentguard.core.deps import ContainerDep, SessionDep
from agentguard.core.errors import PermissionDeniedError
from agentguard.core.events import commit
from agentguard.decisions.schemas import AuthorizeRequest, AuthorizeResponse
from agentguard.identity.dependencies import AgentAuth
from agentguard.identity.models import Agent
from agentguard.users.models import User

router = APIRouter(prefix="/api/v1/approvals", tags=["approvals"])


class VoteOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    stage: int
    user_id: uuid.UUID
    user: str = ""
    vote: str
    comment: str
    at: datetime


class HistoryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    at: datetime
    event: str
    actor: str
    details: dict[str, Any]


class ApprovalOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    created_at: datetime
    agent_id: uuid.UUID
    agent: str = ""
    run_id: uuid.UUID | None
    decision_id: uuid.UUID | None
    tool: str
    action: str
    resource: str
    reason: str
    policy_name: str | None
    policy_version: int | None
    risk_level: str
    status: str
    current_stage: int
    requirement: dict[str, Any]
    on_behalf_of: str | None
    expires_at: datetime
    decided_at: datetime | None
    decision_comment: str | None
    executed_at: datetime | None
    params_preview: dict[str, Any]
    action_hash: str


class ApprovalDetail(ApprovalOut):
    # The exact parameters, for people who may decide (reviewer and up).
    params: dict[str, Any] | None = None
    can_vote: bool = False
    why_not: str | None = None
    votes: list[VoteOut] = Field(default_factory=list)
    history: list[HistoryOut] = Field(default_factory=list)
    result: dict[str, Any] = Field(default_factory=dict)


class VoteIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    comment: str = Field("", max_length=2000)


class CountsOut(BaseModel):
    pending: int
    approved_24h: int
    rejected_24h: int
    expired_24h: int


async def _names(session: SessionDep, ids: set[uuid.UUID]) -> dict[uuid.UUID, str]:
    if not ids:
        return {}
    return dict(
        (await session.execute(select(Agent.id, Agent.slug).where(Agent.id.in_(ids)))).all()
    )


@router.get("", response_model=list[ApprovalOut], summary="Approval requests, pending first")
async def list_approvals(
    actor: StaffRead,
    session: SessionDep,
    status: str | None = Query(
        None,
        pattern="^(pending|approved|rejected|changes_requested|expired|revoked|executed|failed)$",
    ),
    agent_id: uuid.UUID | None = None,
    limit: int = Query(100, ge=1, le=500),
) -> list[ApprovalOut]:
    stmt = select(ApprovalRequest).where(ApprovalRequest.org_id == actor.org_id)
    if status:
        stmt = stmt.where(ApprovalRequest.status == status)
    if agent_id:
        stmt = stmt.where(ApprovalRequest.agent_id == agent_id)
    rows = (
        await session.scalars(
            stmt.order_by(
                (ApprovalRequest.status != "pending"), ApprovalRequest.created_at.desc()
            ).limit(limit)
        )
    ).all()
    names = await _names(session, {r.agent_id for r in rows})
    out = []
    for r in rows:
        item = ApprovalOut.model_validate(r)
        item.agent = names.get(r.agent_id, "")
        out.append(item)
    return out


@router.get("/counts", response_model=CountsOut, summary="Queue counts for badges")
async def counts(actor: StaffRead, session: SessionDep) -> CountsOut:
    since = datetime.now(UTC) - timedelta(hours=24)
    rows = dict(
        (
            await session.execute(
                select(ApprovalRequest.status, func.count())
                .where(
                    ApprovalRequest.org_id == actor.org_id,
                    (ApprovalRequest.status == "pending") | (ApprovalRequest.decided_at >= since),
                )
                .group_by(ApprovalRequest.status)
            )
        ).all()
    )
    return CountsOut(
        pending=int(rows.get("pending", 0)),
        approved_24h=int(rows.get("approved", 0)) + int(rows.get("executed", 0)),
        rejected_24h=int(rows.get("rejected", 0)) + int(rows.get("changes_requested", 0)),
        expired_24h=int(rows.get("expired", 0)),
    )


@router.get(
    "/{approval_id}",
    response_model=ApprovalDetail,
    summary="One request with its exact parameters, votes and history",
)
async def get_approval(
    approval_id: uuid.UUID,
    request: Request,
    actor: StaffRead,
    container: ContainerDep,
    session: SessionDep,
) -> ApprovalDetail:
    row = await service.get(session, actor.org_id, approval_id)
    detail = ApprovalDetail.model_validate(row)
    detail.agent = (await _names(session, {row.agent_id})).get(row.agent_id, "")
    user: User | None = getattr(request.state, "user", None)
    if ROLE_RANK.get(actor.role, -1) >= ROLE_RANK["reviewer"]:
        detail.params = await service.params_of(container, row)
    if user is not None and row.status == "pending":
        why = service.eligible(row, user)
        voted = await session.scalar(
            select(ApprovalVote.id).where(
                ApprovalVote.request_id == row.id,
                ApprovalVote.stage == row.current_stage,
                ApprovalVote.user_id == user.id,
            )
        )
        detail.why_not = "You already voted on this stage" if voted else why
        detail.can_vote = detail.why_not is None
    votes = (
        await session.execute(
            select(ApprovalVote, User.email)
            .join(User, User.id == ApprovalVote.user_id)
            .where(ApprovalVote.request_id == row.id)
            .order_by(ApprovalVote.at)
        )
    ).all()
    detail.votes = [
        VoteOut(**VoteOut.model_validate(v).model_dump(exclude={"user"}), user=email)
        for v, email in votes
    ]
    history = (
        await session.scalars(
            select(ApprovalHistory)
            .where(ApprovalHistory.request_id == row.id)
            .order_by(ApprovalHistory.id)
        )
    ).all()
    detail.history = [HistoryOut.model_validate(h) for h in history]
    detail.result = row.result
    return detail


async def _vote(
    approval_id: uuid.UUID,
    choice: str,
    body: VoteIn,
    request: Request,
    actor: StaffReview,
    container: ContainerDep,
    session: SessionDep,
) -> ApprovalDetail:
    user: User | None = getattr(request.state, "user", None)
    if user is None:
        raise PermissionDeniedError(
            "Approvals are decided by people, not API keys", code="people_only"
        )
    await service.vote(container, session, actor, user, approval_id, choice, body.comment)
    await commit(container, session)
    return await get_approval(approval_id, request, actor, container, session)


@router.post(
    "/{approval_id}/approve",
    response_model=ApprovalDetail,
    summary="Approve (counts toward the current stage)",
)
async def approve(
    approval_id: uuid.UUID,
    body: VoteIn,
    request: Request,
    actor: StaffReview,
    container: ContainerDep,
    session: SessionDep,
) -> ApprovalDetail:
    return await _vote(approval_id, "approve", body, request, actor, container, session)


@router.post(
    "/{approval_id}/reject", response_model=ApprovalDetail, summary="Reject, with a reason"
)
async def reject(
    approval_id: uuid.UUID,
    body: VoteIn,
    request: Request,
    actor: StaffReview,
    container: ContainerDep,
    session: SessionDep,
) -> ApprovalDetail:
    return await _vote(approval_id, "reject", body, request, actor, container, session)


@router.post(
    "/{approval_id}/request-changes",
    response_model=ApprovalDetail,
    summary="Send it back: the agent must ask again with different parameters",
)
async def request_changes(
    approval_id: uuid.UUID,
    body: VoteIn,
    request: Request,
    actor: StaffReview,
    container: ContainerDep,
    session: SessionDep,
) -> ApprovalDetail:
    return await _vote(approval_id, "request_changes", body, request, actor, container, session)


@router.post(
    "/{approval_id}/expire", response_model=ApprovalDetail, summary="Expire a pending request now"
)
async def expire(
    approval_id: uuid.UUID,
    request: Request,
    actor: StaffWrite,
    container: ContainerDep,
    session: SessionDep,
) -> ApprovalDetail:
    await service.expire_now(session, actor, approval_id)
    await commit(container, session)
    return await get_approval(approval_id, request, actor, container, session)


@router.post(
    "/{approval_id}/revoke",
    response_model=ApprovalDetail,
    summary="Emergency: stop an approved request before it is used",
)
async def revoke(
    approval_id: uuid.UUID,
    body: VoteIn,
    request: Request,
    actor: StaffWrite,
    container: ContainerDep,
    session: SessionDep,
) -> ApprovalDetail:
    await service.revoke(session, actor, approval_id, body.comment)
    await commit(container, session)
    return await get_approval(approval_id, request, actor, container, session)


class AskIn(AuthorizeRequest):
    reason: str = Field("", max_length=1000)


@router.post(
    "",
    response_model=AuthorizeResponse,
    status_code=201,
    tags=["agent runtime"],
    summary="An agent asks a person before acting, even where policy would allow it",
)
async def ask(
    body: AskIn,
    principal: AgentAuth,
    request: Request,
    container: ContainerDep,
    session: SessionDep,
) -> AuthorizeResponse:
    """Decides the action like ``authorize``. A denied action stays denied; an allowed one is
    turned into a pending approval request, so an agent unsure of itself can ask a person."""
    from agentguard.core.canonical import action_hash
    from agentguard.core.deps import client_ip
    from agentguard.decisions import pipeline
    from agentguard.protection.detectors import redact_value

    req = AuthorizeRequest(**body.model_dump(exclude={"reason"}))
    response, prepared = await pipeline.authorize(
        container, session, principal, req, source="api", ip=client_ip(request)
    )
    if (
        response.allowed
        and response.would_be in ("allow", "restrict")
        and response.approval is None
    ):
        approval = await service.create(
            container,
            session,
            org_id=principal.org_id,
            agent_id=principal.agent.id,
            agent_slug=principal.agent.slug,
            run_id=prepared.run.id if prepared.run else None,
            decision_id=prepared.decision.id,
            tool=req.tool,
            tool_kind=prepared.tool_kind,
            action=req.action,
            resource=prepared.resource,
            action_hash=action_hash(
                principal.org_id,
                principal.agent.id,
                req.tool,
                req.action,
                prepared.resource,
                req.parameters,
            ),
            params=req.parameters,
            params_preview=redact_value(req.parameters),
            requirement={
                "stages": [
                    {
                        "roles": ["reviewer", "security_officer", "org_admin"],
                        "users": [],
                        "count": 1,
                    }
                ],
                "expires_in_s": 86_400,
                "execute": "auto",
                "forbid_requester": True,
            },
            reason=body.reason or "The agent asked for a person to confirm",
            policy_name=None,
            policy_version=None,
            risk_level=response.risk.get("level", "medium"),
            on_behalf_of=req.on_behalf_of,
        )
        prepared.decision.would_be = prepared.decision.decision = "require_approval"
        prepared.decision.reason_code = "agent_asked"
        prepared.decision.approval_id = approval.id
        response = response.model_copy(
            update={
                "decision": "require_approval",
                "would_be": "require_approval",
                "allowed": False,
                "reason_code": "agent_asked",
                "reason": approval.reason,
                "decision_token": None,
                "approval": {
                    "id": approval.id,
                    "status": "pending",
                    "expires_at": approval.expires_at,
                    "url": f"{container.settings.public_url}/approvals/{approval.id}",
                    "required": approval.requirement["stages"],
                },
            }
        )
    await commit(container, session)
    return response
