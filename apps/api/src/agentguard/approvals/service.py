"""Human approval of sensitive actions.

Lifecycle: the decision pipeline creates a request (``pending``) bound to the action hash
and notifies reviewers. Reviewers vote stage by stage; a stage passes when ``count``
distinct eligible reviewers approved it. Any rejection rejects the request, a request for
changes ends it (the agent must ask again, with different parameters, which is a new hash).
After the last stage the request is ``approved``:

* for tools AgentGuard runs (HTTP, MCP, sandbox) it is executed by the worker, through the
  same pipeline, which re-checks every policy at that moment (a policy that now denies
  wins over the approval);
* for function tools, the agent repeats its request and receives an allow with a decision
  token, once.

Approvals expire, can be revoked in an emergency until they are used, and every event is
appended to ``approval_history``, which the database refuses to change.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import orjson
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from agentguard.approvals.models import FINAL, ApprovalHistory, ApprovalRequest, ApprovalVote
from agentguard.audit.service import Actor, audit
from agentguard.auth.dependencies import ROLE_RANK
from agentguard.core import events, jobs
from agentguard.core.container import Container
from agentguard.core.errors import AppError, ConflictError, NotFoundError, PermissionDeniedError
from agentguard.users.models import User

EXECUTE = "approvals.execute"
NOTIFY = "approvals.notify"
EXPIRE = "approvals.expire"
_CONTEXT = "approval-params:{id}"
AGENTGUARD_RUNS = ("http", "mcp", "sandbox")


def _now() -> datetime:
    return datetime.now(UTC)


def history(
    session: AsyncSession, request: ApprovalRequest, event: str, actor: str, **details: Any
) -> None:
    session.add(
        ApprovalHistory(
            org_id=request.org_id, request_id=request.id, event=event, actor=actor, details=details
        )
    )


async def create(
    container: Container,
    session: AsyncSession,
    *,
    org_id: uuid.UUID,
    agent_id: uuid.UUID,
    agent_slug: str,
    run_id: uuid.UUID | None,
    decision_id: uuid.UUID,
    tool: str,
    tool_kind: str,
    action: str,
    resource: str,
    action_hash: str,
    params: dict[str, Any],
    params_preview: dict[str, Any],
    requirement: dict[str, Any],
    reason: str,
    policy_name: str | None,
    policy_version: int | None,
    risk_level: str,
    on_behalf_of: str | None,
) -> ApprovalRequest:
    execute = requirement.get("execute", "auto")
    if execute == "auto":
        execute = "agentguard" if tool_kind in AGENTGUARD_RUNS else "agent"
    if execute == "agentguard" and tool_kind not in AGENTGUARD_RUNS:
        execute = "agent"
    req_id = uuid.uuid4()
    request = ApprovalRequest(
        id=req_id,
        org_id=org_id,
        decision_id=decision_id,
        agent_id=agent_id,
        run_id=run_id,
        tool=tool,
        action=action,
        resource=resource,
        action_hash=action_hash,
        params_sealed=await container.sealer.seal(
            orjson.dumps(params).decode(), _CONTEXT.format(id=req_id)
        ),
        params_preview=params_preview,
        reason=reason[:1000],
        policy_name=policy_name,
        policy_version=policy_version,
        risk_level=risk_level,
        requirement={**requirement, "execute": execute},
        on_behalf_of=on_behalf_of,
        expires_at=_now() + timedelta(seconds=int(requirement.get("expires_in_s", 86_400))),
    )
    session.add(request)
    await session.flush()
    history(session, request, "created", f"agent:{agent_slug}", reason=reason, policy=policy_name)
    await jobs.enqueue(session, NOTIFY, {"approval_id": str(req_id)}, org_id=org_id, max_attempts=5)
    await jobs.enqueue(
        session,
        EXPIRE,
        {"approval_id": str(req_id)},
        org_id=org_id,
        delay_s=(request.expires_at - _now()).total_seconds() + 1,
        max_attempts=5,
    )
    events.emit(
        session, f"org:{org_id}", {"type": "approval", "id": str(req_id), "status": "pending"}
    )
    from agentguard.integrations.service import dispatch

    await dispatch(
        session,
        org_id,
        "approval.requested",
        {
            "id": str(req_id),
            "agent": agent_slug,
            "tool": tool,
            "action": action,
            "resource": resource,
            "reason": reason,
            "risk": risk_level,
            "expires_at": request.expires_at.isoformat(),
        },
    )
    return request


async def params_of(container: Container, request: ApprovalRequest) -> dict[str, Any]:
    raw = await container.sealer.open(request.params_sealed, _CONTEXT.format(id=request.id))
    value: dict[str, Any] = orjson.loads(raw)
    return value


async def find_for_hash(
    session: AsyncSession, org_id: uuid.UUID, agent_id: uuid.UUID, action_hash: str
) -> ApprovalRequest | None:
    """The newest request for this exact action that is still meaningful to the agent."""
    return await session.scalar(
        select(ApprovalRequest)
        .where(
            ApprovalRequest.org_id == org_id,
            ApprovalRequest.agent_id == agent_id,
            ApprovalRequest.action_hash == action_hash,
            ApprovalRequest.status.in_(("pending", "approved", "rejected", "changes_requested")),
            ApprovalRequest.expires_at > _now(),
        )
        .order_by(ApprovalRequest.created_at.desc())
        .limit(1)
    )


async def get(
    session: AsyncSession, org_id: uuid.UUID, approval_id: uuid.UUID, *, lock: bool = False
) -> ApprovalRequest:
    stmt = select(ApprovalRequest).where(ApprovalRequest.id == approval_id)
    if lock:
        stmt = stmt.with_for_update()
    request = await session.scalar(stmt)
    if request is None or request.org_id != org_id:
        raise NotFoundError("Approval not found")
    return request


def eligible(request: ApprovalRequest, user: User) -> str | None:
    """Why this user may not vote on the current stage, or None."""
    stages = request.requirement.get("stages") or []
    if request.current_stage >= len(stages):
        return "This request has no open stage"
    stage = stages[request.current_stage]
    if ROLE_RANK.get(user.role, -1) < ROLE_RANK["reviewer"]:
        return "Auditors cannot decide approvals"
    by_role = user.role in (stage.get("roles") or [])
    by_name = user.email.lower() in [u.lower() for u in stage.get("users") or []]
    if not by_role and not by_name:
        who = ", ".join([*(stage.get("roles") or []), *(stage.get("users") or [])])
        return f"This stage needs {who}"
    if (
        request.requirement.get("forbid_requester", True)
        and request.on_behalf_of
        and request.on_behalf_of.lower() == user.email.lower()
    ):
        return "You cannot approve an action taken on your own behalf"
    return None


async def vote(
    container: Container,
    session: AsyncSession,
    actor: Actor,
    user: User,
    approval_id: uuid.UUID,
    choice: str,
    comment: str,
) -> ApprovalRequest:
    if choice not in ("approve", "reject", "request_changes"):
        raise AppError("Vote approve, reject or request_changes", code="invalid_vote")
    request = await get(session, actor.org_id, approval_id, lock=True)
    if request.status != "pending":
        raise ConflictError(
            f"This request is already {request.status.replace('_', ' ')}", code="not_pending"
        )
    if request.expires_at <= _now():
        await _expire(session, request)
        await session.commit()
        raise ConflictError("This request expired", code="expired")
    problem = eligible(request, user)
    if problem:
        raise PermissionDeniedError(problem, code="not_eligible")
    if choice in ("reject", "request_changes") and not comment.strip():
        raise AppError(
            "Say why, so the agent and its owner know what to change", code="comment_required"
        )
    already = await session.scalar(
        select(ApprovalVote.id).where(
            ApprovalVote.request_id == request.id,
            ApprovalVote.stage == request.current_stage,
            ApprovalVote.user_id == user.id,
        )
    )
    if already:
        raise ConflictError("You already voted on this stage", code="already_voted")
    session.add(
        ApprovalVote(
            org_id=request.org_id,
            request_id=request.id,
            stage=request.current_stage,
            user_id=user.id,
            vote=choice,
            comment=comment[:2000],
        )
    )
    history(
        session, request, f"vote.{choice}", user.email, stage=request.current_stage, comment=comment
    )
    audit(session, actor, f"approval.{choice}", "approval", request.id, stage=request.current_stage)
    if choice != "approve":
        request.status = "rejected" if choice == "reject" else "changes_requested"
        request.decided_at = _now()
        request.decided_by = user.id
        request.decision_comment = comment
        history(session, request, request.status, user.email, comment=comment)
        await _decided(session, request)
        return request
    await session.flush()
    stage = request.requirement["stages"][request.current_stage]
    approvals = await session.scalar(
        select(func.count())
        .select_from(ApprovalVote)
        .where(
            ApprovalVote.request_id == request.id,
            ApprovalVote.stage == request.current_stage,
            ApprovalVote.vote == "approve",
        )
    )
    if int(approvals or 0) >= int(stage.get("count", 1)):
        history(session, request, "stage.passed", "agentguard", stage=request.current_stage)
        request.current_stage += 1
        if request.current_stage >= len(request.requirement["stages"]):
            request.status = "approved"
            request.decided_at = _now()
            request.decided_by = user.id
            request.decision_comment = comment or None
            history(session, request, "approved", user.email)
            await _decided(session, request)
            if request.requirement.get("execute") == "agentguard":
                await jobs.enqueue(
                    session,
                    EXECUTE,
                    {"approval_id": str(request.id)},
                    org_id=request.org_id,
                    max_attempts=3,
                    dedupe_key=f"approval-exec:{request.id}",
                )
        else:
            await jobs.enqueue(
                session,
                NOTIFY,
                {"approval_id": str(request.id)},
                org_id=request.org_id,
                max_attempts=5,
            )
    events.emit(
        session,
        f"org:{request.org_id}",
        {"type": "approval", "id": str(request.id), "status": request.status},
    )
    return request


async def _decided(session: AsyncSession, request: ApprovalRequest) -> None:
    from agentguard.integrations.service import dispatch

    events.emit(
        session,
        f"org:{request.org_id}",
        {"type": "approval", "id": str(request.id), "status": request.status},
    )
    events.emit(session, f"approval:{request.id}", {"type": "approval", "status": request.status})
    await dispatch(
        session,
        request.org_id,
        "approval.decided",
        {
            "id": str(request.id),
            "status": request.status,
            "comment": request.decision_comment,
            "tool": request.tool,
            "action": request.action,
        },
    )


async def _expire(session: AsyncSession, request: ApprovalRequest) -> None:
    request.status = "expired"
    request.decided_at = _now()
    history(session, request, "expired", "agentguard")
    await _decided(session, request)


async def revoke(
    session: AsyncSession, actor: Actor, approval_id: uuid.UUID, reason: str
) -> ApprovalRequest:
    """Emergency stop: a pending or approved-but-unused request can no longer run."""
    request = await get(session, actor.org_id, approval_id, lock=True)
    if request.status not in ("pending", "approved"):
        raise ConflictError(f"A {request.status} request cannot be revoked", code="not_revocable")
    if not reason.strip():
        raise AppError("Say why you are revoking it", code="comment_required")
    request.status = "revoked"
    request.decided_at = _now()
    request.decision_comment = reason
    history(session, request, "revoked", actor.label, reason=reason)
    audit(session, actor, "approval.revoked", "approval", request.id, reason=reason)
    await _decided(session, request)
    return request


async def expire_now(
    session: AsyncSession, actor: Actor, approval_id: uuid.UUID
) -> ApprovalRequest:
    request = await get(session, actor.org_id, approval_id, lock=True)
    if request.status != "pending":
        raise ConflictError(f"A {request.status} request cannot be expired", code="not_pending")
    await _expire(session, request)
    audit(session, actor, "approval.expired", "approval", request.id)
    return request


async def consume(
    session: AsyncSession, request: ApprovalRequest, decision_id: uuid.UUID, actor: str
) -> bool:
    """Mark an approved request used, exactly once (a concurrent second use gets False)."""
    result = await session.execute(
        update(ApprovalRequest)
        .where(ApprovalRequest.id == request.id, ApprovalRequest.status == "approved")
        .values(status="executed", executed_at=_now(), execution_decision_id=decision_id)
        .returning(ApprovalRequest.id)
    )
    if result.scalar() is None:
        return False
    request.status = "executed"
    history(session, request, "executed", actor, decision_id=str(decision_id))
    events.emit(session, f"approval:{request.id}", {"type": "approval", "status": "executed"})
    events.emit(
        session,
        f"org:{request.org_id}",
        {"type": "approval", "id": str(request.id), "status": "executed"},
    )
    return True


@jobs.handles(EXPIRE)
async def expire_job(ctx: jobs.JobContext) -> None:
    async with ctx.container.db.sessionmaker() as session:
        request = await session.get(
            ApprovalRequest, uuid.UUID(ctx.payload["approval_id"]), with_for_update=True
        )
        if request is None or request.status != "pending" or request.expires_at > _now():
            return
        await _expire(session, request)
        from agentguard.core.events import commit

        await commit(ctx.container, session)


async def expire_overdue(container: Container) -> int:
    """Periodic safety net for expiry jobs (a deleted job row, a clock jump)."""
    async with container.db.sessionmaker() as session:
        rows = (
            await session.scalars(
                select(ApprovalRequest)
                .where(ApprovalRequest.status == "pending", ApprovalRequest.expires_at <= _now())
                .with_for_update(skip_locked=True)
                .limit(500)
            )
        ).all()
        for request in rows:
            await _expire(session, request)
        from agentguard.core.events import commit

        await commit(container, session)
        return len(rows)


async def reviewers_for(session: AsyncSession, request: ApprovalRequest) -> list[User]:
    stages = request.requirement.get("stages") or []
    if request.current_stage >= len(stages):
        return []
    stage = stages[request.current_stage]
    roles = stage.get("roles") or []
    emails = [u.lower() for u in stage.get("users") or []]
    users = (
        await session.scalars(
            select(User).where(User.org_id == request.org_id, User.disabled.is_(False))
        )
    ).all()
    return [
        u
        for u in users
        if (u.role in roles or u.email.lower() in emails)
        and not (request.on_behalf_of and u.email.lower() == request.on_behalf_of.lower())
    ]


def is_final(status: str) -> bool:
    return status in FINAL
