"""The decision pipeline: one authorize request in, one recorded decision out.

Order (each step can only add caution; a step that decides stops the policy evaluation but
everything is still recorded):

1. the agent's status (suspended, quarantined) and the organisation's kill switch;
2. the tool: registered, active, the action supported, the parameters valid;
3. the resource: built from the parameters, looked up for sensitivity and ownership;
4. the run: counted, aged, its taint read; personal data and credentials in the parameters;
5. limits (atomic), the loop guard, TokenShield budgets;
6. risk;
7. policies (and OPA if connected), deny-overrides, then permissions, then the default;
8. approvals: an approved request for this exact action is redeemed once; a pending one is
   returned again; otherwise a new request is created;
9. the decision is recorded with its reason, policy version and redacted input, an audit
   record is chained, a decision token is minted when the tool needs one.

Everything is written in the caller's transaction; the caller commits.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from agentguard.access.resolve import for_agent
from agentguard.approvals import service as approvals
from agentguard.audit.service import agent_actor, audit, system_actor
from agentguard.core import events
from agentguard.core.canonical import action_hash
from agentguard.core.container import Container
from agentguard.decisions import config as org_config
from agentguard.decisions.config import OrgConfig
from agentguard.decisions.models import Decision, DecisionToken, Run
from agentguard.decisions.schemas import Approval, AuthorizeRequest, AuthorizeResponse
from agentguard.identity import service as identity
from agentguard.identity.models import Agent
from agentguard.identity.service import AgentPrincipal
from agentguard.limits import service as limits
from agentguard.org import service as org_service
from agentguard.org.models import Project
from agentguard.policies import engine
from agentguard.policies.service import active_policies
from agentguard.protection.detectors import data_classes, redact_value, scan_value
from agentguard.risk import engine as risk_engine
from agentguard.threats import service as threats
from agentguard.tools.models import Tool
from agentguard.tools.validation import render_resource, validate

log = logging.getLogger("agentguard.decisions")

DECISION_TOKEN_TYP = "agd+jwt"  # noqa: S105 a JWT type name
DECISION_AUDIENCE = "agentguard-decision"
WEEKDAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(slots=True)
class Prepared:
    """Everything the pipeline learned, for the execution adapters that follow."""

    agent: Agent
    tool: Tool | None
    tool_kind: str
    params: dict[str, Any]
    resource: str
    run: Run | None
    data: dict[str, Any]
    hash: str
    decision: Decision
    approval_consumed: bool = False
    obligations: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Pre:
    decision: str
    code: str
    reason: str
    reasons: list[str] = field(default_factory=list)


async def upsert_run(
    session: AsyncSession, agent: Agent, run_key: str, on_behalf_of: str | None
) -> tuple[Run, bool]:
    stmt = (
        insert(Run)
        .values(
            id=uuid.uuid4(),
            org_id=agent.org_id,
            agent_id=agent.id,
            run_key=run_key,
            tool_calls=1,
            on_behalf_of=on_behalf_of,
        )
        .on_conflict_do_update(
            constraint="uq_runs_agent_key",
            set_={"tool_calls": Run.tool_calls + 1, "last_at": func.now()},
        )
        .returning(Run, text("(xmax = 0) AS inserted"))
    )
    # One round trip: the row comes back with the upsert (populated into the session).
    row = (await session.execute(stmt, execution_options={"populate_existing": True})).one()
    return row[0], bool(row[1])


async def _active_runs(session: AsyncSession, agent_id: uuid.UUID, idle_s: int) -> int:
    cutoff = _now() - timedelta(seconds=idle_s)
    return int(
        await session.scalar(
            select(func.count())
            .select_from(Run)
            .where(Run.agent_id == agent_id, Run.ended_at.is_(None), Run.last_at > cutoff)
        )
        or 0
    )


def _tool_info(tool: Tool | None, name: str) -> dict[str, Any]:
    if tool is None:
        return {
            "name": name,
            "kind": "unknown",
            "risk": "medium",
            "sensitive": False,
            "external": False,
            "registered": False,
        }
    return {
        "name": tool.name,
        "kind": tool.kind,
        "risk": tool.risk,
        "sensitive": tool.sensitive,
        "external": tool.external,
        "registered": True,
        "actions": list(tool.actions),
    }


@dataclass(slots=True)
class Target:
    tool: Tool | None
    tool_kind: str
    resource_key: str
    resource: Any
    project: Project
    resource_project: str | None
    pre: Pre | None


async def resolve_target(
    config: OrgConfig, agent: Agent, req: AuthorizeRequest, require_registered: bool
) -> Target:
    """The tool, its validation, the resource and the projects involved (no queries)."""
    pre: Pre | None = None
    tool = config.tools.get(req.tool)
    tool_kind = tool.kind if tool else "unknown"
    if tool is None:
        if require_registered:
            pre = Pre("deny", "unknown_tool", f"{req.tool} is not a registered tool")
    elif tool.status == "disabled":
        pre = Pre("deny", "tool_disabled", f"{tool.name} is disabled")
    elif tool.status == "pending_review":
        pre = Pre(
            "deny", "tool_pending_review", f"{tool.name} changed upstream and waits for review"
        )
    elif tool.actions and req.action not in tool.actions:
        pre = Pre(
            "deny",
            "unknown_action",
            f"{tool.name} supports {', '.join(tool.actions)}, not {req.action}",
        )
    params = req.parameters
    if pre is None and tool is not None:
        problems = validate(params, tool.input_schema, tool.constraints)
        if problems:
            pre = Pre(
                "deny", "invalid_parameters", "The parameters are not valid for this tool", problems
            )
    resource_key = req.resource or ""
    if not resource_key and tool is not None and tool.resource_template:
        try:
            resource_key = render_resource(tool.resource_template, params)
        except ValueError as exc:
            pre = pre or Pre("deny", "invalid_parameters", str(exc), [str(exc)])
    resource = config.resource(resource_key)
    project = config.projects[agent.project_id]
    resource_project: str | None = None
    if resource is not None and resource.project_id is not None:
        owner = config.projects.get(resource.project_id)
        resource_project = owner.slug if owner else str(resource.project_id)
    return Target(tool, tool_kind, resource_key, resource, project, resource_project, pre)


@dataclass(slots=True)
class Built:
    data: dict[str, Any]
    classes: list[str]
    granted: Any
    assessment: risk_engine.Assessment
    hash: str
    repeats: int = 0
    burst: int = 0


async def build_input(
    container: Container,
    session: AsyncSession,
    agent: Agent,
    req: AuthorizeRequest,
    target: Target,
    run: Run | None,
    *,
    config: OrgConfig,
    source: str,
    ip: str | None,
    count: bool = True,
) -> Built:
    """The evaluation input policies, permissions and risk rules see (reads only)."""
    org_id = agent.org_id
    org_slug = config.org_slug
    tool, resource, project = target.tool, target.resource, target.project
    resource_key, resource_project = target.resource_key, target.resource_project
    params = req.parameters
    findings = scan_value(params)
    classes = data_classes(findings)
    open_threats = await threats.open_count(session, agent.id)
    hash_ = action_hash(org_id, agent.id, req.tool, req.action, resource_key, params)
    # One round trip for the three counters: recent denials (read only), identical repeats
    # in this run and calls of this tool per minute (counted unless this is a dry run).
    step = 1 if count else 0
    recent_denies, repeats, burst = await container.kv.window_many(
        [
            (f"denies:{agent.id}", 0, 600),
            (f"loop:{run.id if run else agent.id}:{hash_}", step, 300),
            (f"burst:{agent.id}:{req.tool}", step, 60),
        ]
    )
    granted = await for_agent(container, session, org_id, agent.project_id, agent.id, config.gen)
    now = _now()
    data: dict[str, Any] = {
        "agent": {
            "id": str(agent.id),
            "slug": agent.slug,
            "name": agent.name,
            "project": project.slug,
            "labels": dict(agent.labels),
            "roles": granted.roles,
            "framework": agent.framework,
            "history": {"open_threats": open_threats, "recent_denies": recent_denies},
        },
        "org": {"slug": org_slug},
        "project": {"slug": project.slug, "environment": project.environment},
        "tool": _tool_info(tool, req.tool),
        "action": req.action,
        "resource": {
            "key": resource_key,
            "registered": resource is not None,
            "type": resource.type
            if resource
            else (resource_key.split(":", 1)[0] if ":" in resource_key else ""),
            "sensitivity": resource.sensitivity if resource else "internal",
            "environment": resource.environment if resource else project.environment,
            "data_classes": list(resource.data_classes) if resource else [],
            "project": resource_project,
            "owned": resource is None
            or resource.project_id is None
            or resource.project_id == project.id,
            "tags": dict(resource.tags) if resource else {},
        },
        "params": params,
        "context": {
            **req.context,
            "data_classes": classes,
            "pii_count": sum(1 for f in findings if f.data_class == "pii"),
            "on_behalf_of": req.on_behalf_of,
            "source": source,
            "ip": ip,
        },
        "run": {
            "id": req.run_id,
            "tainted": bool(run and run.tainted_at),
            "taint": dict(run.taint) if run else {},
            "calls": run.tool_calls if run else 0,
            "age_s": int((now - run.started_at).total_seconds()) if run else 0,
        },
        "time": {
            "hour": now.hour,
            "weekday": WEEKDAYS[now.weekday()],
            "date": now.date().isoformat(),
            "iso": now.isoformat(),
        },
    }
    assessment = risk_engine.assess(data, config.risk_rules)
    data["risk"] = {"level": assessment.level, "score": assessment.score}
    return Built(data, classes, granted, assessment, hash_, repeats, burst)


async def _check_approval_tenant(
    session: AsyncSession, org_id: uuid.UUID, agent: Agent, approval_id: uuid.UUID
) -> None:
    """An approval id from another organisation is a cross-tenant probe: refuse and record."""
    from agentguard.approvals.models import ApprovalRequest
    from agentguard.core.errors import NotFoundError

    owner = await session.scalar(
        select(ApprovalRequest.org_id).where(ApprovalRequest.id == approval_id)
    )
    if owner == org_id:
        return
    if owner is not None:
        await threats.record(
            session,
            org_id,
            kind="cross_tenant",
            severity="high",
            rule="foreign_approval_id",
            summary=f"{agent.slug} presented an approval of another organisation",
            agent_id=agent.id,
            details={"approval_id": str(approval_id)},
            dedupe="foreign_approval",
        )
        await session.commit()
    raise NotFoundError("Approval not found")


async def authorize(
    container: Container,
    session: AsyncSession,
    principal: AgentPrincipal,
    req: AuthorizeRequest,
    *,
    source: str = "api",
    ip: str | None = None,
) -> tuple[AuthorizeResponse, Prepared]:
    started = time.perf_counter()
    agent = principal.agent
    org_id = agent.org_id
    settings = await org_service.load(session, org_id)
    enforcement = settings.enforcement
    mode = enforcement.mode
    pre: Pre | None = None

    if req.approval_id is not None:
        await _check_approval_tenant(session, org_id, agent, req.approval_id)
    if agent.status != "active":
        pre = Pre(
            "deny",
            f"agent_{agent.status}",
            f"The agent is {agent.status}: {agent.status_reason or 'no reason given'}",
        )
    elif settings.kill_switch.active:
        pre = Pre(
            "deny",
            "kill_switch",
            f"The organisation's kill switch is on: {settings.kill_switch.reason}",
        )

    config = await org_config.load(container, session, org_id)
    target = await resolve_target(
        config, agent, req, enforcement.require_registered_tools or mode == "enforce"
    )
    tool, tool_kind, params = target.tool, target.tool_kind, req.parameters
    resource_key, project = target.resource_key, target.project
    if pre is None and target.pre is not None:
        pre = target.pre

    run: Run | None = None
    new_run = False
    if req.run_id:
        if any(lim.metric == "concurrent_runs" for lim in config.limits):
            # Count and insert under one lock per agent, so concurrent starts are exact.
            await session.execute(
                text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": f"runs:{agent.id}"}
            )
        run, new_run = await upsert_run(session, agent, req.run_id, req.on_behalf_of)

    built = await build_input(
        container, session, agent, req, target, run, config=config, source=source, ip=ip
    )
    data, classes, granted, assessment, hash_ = (
        built.data,
        built.classes,
        built.granted,
        built.assessment,
        built.hash,
    )

    subject = limits.Subject(org_id, agent.project_id, agent.id, agent.slug, req.on_behalf_of)
    org_limits = config.limits
    if pre is None:
        violations = await limits.check(
            container,
            org_limits,
            subject,
            run_calls=run.tool_calls if run else 0,
            run_started_at=run.started_at if run else None,
            concurrent_runs=await _active_runs(session, agent.id, enforcement.run_idle_s)
            if new_run
            else 0,
            sandbox_memory_mb=memory
            if tool_kind == "sandbox" and isinstance(memory := params.get("memory_mb"), int)
            else None,
        )
        if violations:
            v = violations[0]
            pre = Pre(
                "deny",
                "limit_exceeded",
                f"Limit {v.name} reached ({v.metric}: {v.value} of {v.limit})",
                [str(x.as_dict()) for x in violations],
            )
            if any(x.on_exceed == "suspend" for x in violations) and mode == "enforce":
                await identity.set_status(
                    session,
                    system_actor(org_id, "limits"),
                    agent,
                    "suspended",
                    f"Limit {v.name} exceeded",
                )
                await threats.record(
                    session,
                    org_id,
                    kind="resource_exhaustion",
                    severity="medium",
                    rule="limit_suspend",
                    summary=f"{agent.slug} exceeded {v.name} and was suspended",
                    agent_id=agent.id,
                    run_id=run.id if run else None,
                    details=v.as_dict(),
                    dedupe=v.name,
                    respond=False,
                )
    if pre is None:
        repeats = built.repeats
        if repeats > enforcement.loop_threshold:
            pre = Pre(
                "deny",
                "loop_detected",
                f"The same action was requested {repeats} times in five minutes",
            )
            await threats.record(
                session,
                org_id,
                kind="agent_loop",
                severity="medium",
                rule="identical_repeats",
                summary=f"{agent.slug} repeated {req.tool}.{req.action} {repeats} times",
                agent_id=agent.id,
                run_id=run.id if run else None,
                details={"repeats": repeats, "tool": req.tool},
                dedupe=hash_[:16],
            )
        burst = built.burst
        if burst == enforcement.burst_per_minute + 1:
            await threats.record(
                session,
                org_id,
                kind="tool_abuse",
                severity="medium",
                rule="burst",
                summary=f"{agent.slug} called {req.tool} more than {enforcement.burst_per_minute} times in a minute",
                agent_id=agent.id,
                details={"per_minute": burst},
                dedupe=req.tool,
            )
    if pre is None:
        from agentguard.integrations import tokenshield

        ts = config.tokenshield
        if ts is not None:
            budget = await tokenshield.state(container, ts, project.slug)
            if budget is not None and budget.exhausted:
                pre = Pre("deny", "budget_exhausted", budget.detail)

    grants_record = [
        {
            "role": g.role,
            "tool": g.tool,
            "actions": list(g.actions),
            "resource": g.resource,
            "condition": g.condition,
        }
        for g in granted.grants
    ]
    default = enforcement.default_decision if mode == "audit" else "deny"
    outcome: engine.Outcome
    if pre is not None:
        outcome = engine.Outcome(decision=pre.decision, reason_code=pre.code, reason=pre.reason)
    else:
        outcome = engine.evaluate(
            await active_policies(container, session, org_id, config.gen),
            granted.grants,
            data,
            default=default,
        )
        from agentguard.integrations import opa

        opa_row = config.opa
        if opa_row is not None:
            result = await opa.evaluate(container, opa_row, org_id, _plain(data))
            if result.error:
                if tool is not None and tool.sensitive:
                    outcome = engine.Outcome(
                        "deny", "opa_unavailable", result.error, matched=outcome.matched
                    )
            elif (
                result.decision
                and engine.STRENGTH[result.decision] > engine.STRENGTH[outcome.decision]
            ):
                outcome = engine.Outcome(
                    result.decision,
                    f"opa_{result.decision}",
                    result.reason,
                    matched=outcome.matched,
                    approval={
                        "stages": [
                            {"roles": ["security_officer", "org_admin"], "users": [], "count": 1}
                        ],
                        "expires_in_s": 86_400,
                        "execute": "auto",
                        "forbid_requester": True,
                    }
                    if result.decision == "require_approval"
                    else None,
                )

    decision_id = uuid.uuid4()
    # The row exists before anything that refers to it (an approval request) is flushed;
    # its outcome fields are filled in below.
    record = Decision(
        id=decision_id,
        org_id=org_id,
        agent_id=agent.id,
        run_id=run.id if run else None,
        source=source,
        tool=req.tool,
        action=req.action,
        resource=resource_key,
        action_hash=hash_,
        decision="deny",
        would_be="deny",
        mode=mode,
        reason_code="pending",
        on_behalf_of=req.on_behalf_of,
    )
    session.add(record)
    final = outcome.decision
    reason_code = outcome.reason_code
    reason = outcome.reason
    # Every rule that agreed on the winning decision, so a reviewer sees all of them.
    reasons = (
        pre.reasons
        if pre
        else list(
            dict.fromkeys(m.reason for m in outcome.matched if m.decision == outcome.decision)
        )
    )
    approval_row = None
    consumed = False
    if final == "require_approval" and mode == "enforce":
        existing = None
        if req.approval_id is not None:
            existing = await approvals.get(session, org_id, req.approval_id, lock=True)
            if existing.agent_id != agent.id or existing.action_hash != hash_:
                final, reason_code = "deny", "approval_mismatch"
                reason = "That approval was given for a different action; any change to an approved action needs a new approval"
                existing = None
        else:
            existing = await approvals.find_for_hash(session, org_id, agent.id, hash_)
        if final == "require_approval" and existing is not None:
            approval_row = existing
            runs_itself = existing.requirement.get("execute") == "agentguard"
            if existing.status == "approved" and runs_itself and req.approval_id != existing.id:
                # AgentGuard runs this one itself (the worker names the approval); the agent
                # waits for the result instead of racing it.
                reason = "Approved; AgentGuard is running it. Wait for the approval's result"
            elif existing.status == "approved":
                if await approvals.consume(session, existing, decision_id, f"agent:{agent.slug}"):
                    final, reason_code, consumed = "allow", "approved", True
                    reason = f"Approved for this exact action: {existing.reason}"
                else:
                    final, reason_code = "deny", "approval_used"
                    reason = "That approval was already used"
            elif existing.status == "rejected":
                final, reason_code = "deny", "approval_rejected"
                reason = (
                    f"A reviewer rejected this action: {existing.decision_comment or ''}".strip()
                )
            elif existing.status == "changes_requested":
                final, reason_code = "deny", "changes_requested"
                reason = f"A reviewer asked for changes: {existing.decision_comment or ''}".strip()
        if final == "require_approval" and approval_row is None:
            # The request refers to the decision: insert it first (no relationship orders it).
            await session.flush()
            approval_row = await approvals.create(
                container,
                session,
                org_id=org_id,
                agent_id=agent.id,
                agent_slug=agent.slug,
                run_id=run.id if run else None,
                decision_id=decision_id,
                tool=req.tool,
                tool_kind=tool_kind,
                action=req.action,
                resource=resource_key,
                action_hash=hash_,
                params=params,
                params_preview=redact_value(params),
                requirement=outcome.approval
                or {
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
                reason=reason,
                policy_name=outcome.deciding.policy if outcome.deciding else None,
                policy_version=outcome.deciding.version if outcome.deciding else None,
                risk_level=assessment.level,
                on_behalf_of=req.on_behalf_of,
            )
    elif final == "require_approval" and mode == "audit" and req.approval_id is not None:
        # Audit mode never holds an action, but an explicit redemption is still checked.
        approval_row = await approvals.get(session, org_id, req.approval_id)

    would_be = final
    decision = final if mode == "enforce" else "allow"
    if would_be == "quarantine" and mode == "enforce" and agent.status == "active":
        await identity.set_status(
            session, system_actor(org_id, "policy"), agent, "quarantined", reason
        )
        await threats.record(
            session,
            org_id,
            kind="unauthorized_access",
            severity="high",
            rule="policy_quarantine",
            summary=f"Policy quarantined {agent.slug}: {reason}",
            agent_id=agent.id,
            run_id=run.id if run else None,
            decision_id=decision_id,
            respond=False,
        )
    deciding = outcome.deciding
    stored_context = {
        **_plain({**data, "params": redact_value(params)}),
        "_grants": grants_record,
        "_default": default,
        "_prechecked": pre is not None,
    }
    record.decision = decision
    record.would_be = would_be
    record.reason_code = reason_code
    record.reasons = reasons
    record.policy_id = (
        uuid.UUID(deciding.policy_id) if deciding and deciding.policy_id != "draft" else None
    )
    record.policy_name = deciding.policy if deciding else None
    record.policy_version = deciding.version if deciding else None
    record.matched = [m.as_dict() for m in outcome.matched]
    record.risk_level = assessment.level
    record.risk_score = assessment.score
    record.risk_factors = assessment.factors
    record.data_classes = classes
    record.obligations = outcome.obligations if final in ("restrict", "allow") else {}
    record.approval_id = approval_row.id if approval_row else None
    record.params = redact_value(params)
    record.context = stored_context
    if run is not None and would_be in ("deny", "quarantine"):
        run.denied += 1
    actor = agent_actor(org_id, agent.id, agent.slug, ip)
    audit(
        session,
        actor,
        f"decision.{would_be}",
        "decision",
        decision_id,
        tool=req.tool,
        action=req.action,
        resource=resource_key,
        reason=reason_code,
        policy=deciding.policy if deciding else None,
        version=deciding.version if deciding else None,
        mode=mode,
        risk=assessment.level,
    )
    if would_be in ("deny", "quarantine"):
        await limits.count_failure(container, org_limits, subject)
        _, denies = await container.kv.window_add(f"denies:{agent.id}", 1, None, 600)
        if denies == enforcement.deny_streak and reason_code in (
            "no_permission",
            "policy_deny",
            "resource_not_owned",
        ):
            await threats.record(
                session,
                org_id,
                kind="privilege_escalation",
                severity="high",
                rule="deny_streak",
                summary=f"{agent.slug} was denied {denies} times in ten minutes, probing for permissions",
                agent_id=agent.id,
                run_id=run.id if run else None,
                decision_id=decision_id,
                details={"denies": denies, "last_tool": req.tool},
                dedupe="deny_streak",
            )
        from agentguard.integrations.service import dispatch

        await dispatch(
            session,
            org_id,
            "decision.denied",
            {
                "decision_id": str(decision_id),
                "agent": agent.slug,
                "tool": req.tool,
                "action": req.action,
                "reason_code": reason_code,
                "reason": reason,
            },
        )

    token: str | None = None
    expires_at: datetime | None = None
    if (
        decision in ("allow", "restrict")
        and would_be in ("allow", "restrict")
        and (tool_kind == "function" or req.want_token or enforcement.always_issue_tokens)
    ):
        token, expires_at = await _mint(
            container, session, record, agent, outcome.obligations if final == "restrict" else {}
        )
    elif approval_row is not None and would_be == "require_approval":
        expires_at = approval_row.expires_at

    log.info(
        "decision",
        extra={
            "decision": would_be,
            "mode": mode,
            "agent": agent.slug,
            "tool": req.tool,
            "action": req.action,
            "reason_code": reason_code,
            "org_id": str(org_id),
        },
    )
    elapsed = (time.perf_counter() - started) * 1000
    record.latency_ms = round(elapsed, 3)
    events.emit(
        session,
        f"org:{org_id}",
        {
            "type": "decision",
            "id": str(decision_id),
            "decision": would_be,
            "agent": agent.slug,
            "tool": req.tool,
        },
    )
    approval_out = None
    if approval_row is not None:
        approval_out = Approval(
            id=approval_row.id,
            status=approval_row.status,
            expires_at=approval_row.expires_at,
            url=f"{container.settings.public_url}/approvals/{approval_row.id}",
            required=list(approval_row.requirement.get("stages") or []),
            comment=approval_row.decision_comment,
        )
    response = AuthorizeResponse(
        decision_id=decision_id,
        decision=decision,
        allowed=decision in ("allow", "restrict"),
        would_be=would_be,
        mode=mode,
        reason_code=reason_code,
        reason=reason,
        reasons=reasons,
        policy_id=record.policy_id,
        policy=record.policy_name,
        policy_version=record.policy_version,
        obligations=record.obligations,
        risk={"level": assessment.level, "score": assessment.score, "factors": assessment.factors},
        data_classes=classes,
        action_hash=hash_,
        approval=approval_out,
        decision_token=token,
        expires_at=expires_at,
        run_id=req.run_id,
    )
    prepared = Prepared(
        agent=agent,
        tool=tool,
        tool_kind=tool_kind,
        params=params,
        resource=resource_key,
        run=run,
        data=data,
        hash=hash_,
        decision=record,
        approval_consumed=consumed,
        obligations=record.obligations,
    )
    return response, prepared


def _plain(value: Any) -> Any:
    import orjson

    return orjson.loads(orjson.dumps(value, default=str))


async def _mint(
    container: Container,
    session: AsyncSession,
    record: Decision,
    agent: Agent,
    obligations: dict[str, Any],
) -> tuple[str, datetime]:
    import secrets

    now = _now()
    expires = now + timedelta(seconds=container.settings.decision_token_ttl_s)
    jti = secrets.token_hex(16)
    token = await container.keys.sign_jwt(
        {
            "iss": container.settings.public_api_url,
            "aud": DECISION_AUDIENCE,
            "sub": str(agent.id),
            "org": str(agent.org_id),
            "agent": agent.slug,
            "did": str(record.id),
            "tool": record.tool,
            "act": record.action,
            "res": record.resource,
            "ah": record.action_hash,
            "obl": obligations,
            "iat": now,
            "exp": expires,
            "jti": jti,
        },
        typ=DECISION_TOKEN_TYP,
    )
    session.add(
        DecisionToken(
            jti=jti,
            org_id=agent.org_id,
            decision_id=record.id,
            action_hash=record.action_hash,
            expires_at=expires,
        )
    )
    return token, expires
