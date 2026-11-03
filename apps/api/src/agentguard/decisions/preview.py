"""A dry run of the decision pipeline for the policy builder.

Builds the same evaluation input the pipeline would (tool, validation, resource, project,
permissions, risk) and evaluates the active policies, optionally with a draft added, but
writes nothing and counts nothing: no decision record, no approval request, no limit or
loop counters, no threats.
"""

from __future__ import annotations

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from agentguard.core.container import Container
from agentguard.core.errors import AppError, NotFoundError
from agentguard.decisions import config as org_config
from agentguard.decisions import pipeline
from agentguard.decisions.schemas import EvaluateRequest, EvaluateResponse
from agentguard.identity.service import agent_by_slug
from agentguard.org import service as org_service
from agentguard.policies import engine
from agentguard.policies.dsl import PolicyError, compile_policy
from agentguard.policies.service import active_policies
from agentguard.protection.detectors import redact_value


async def preview(
    container: Container, session: AsyncSession, org_id: uuid.UUID, body: EvaluateRequest
) -> EvaluateResponse:
    agent = await agent_by_slug(session, org_id, body.agent)
    if agent is None:
        raise NotFoundError(f"No agent named {body.agent}")
    bundle = await org_service.load(session, org_id)
    mode = bundle.enforcement.mode
    req = body.request
    config = await org_config.load(container, session, org_id)
    target = await pipeline.resolve_target(
        config, agent, req, bundle.enforcement.require_registered_tools or mode == "enforce"
    )
    built = await pipeline.build_input(
        container,
        session,
        agent,
        req,
        target,
        None,
        config=config,
        source="preview",
        ip=None,
        count=False,
    )
    policies = await active_policies(container, session, org_id)
    if body.draft:
        try:
            draft = compile_policy(body.draft)
        except PolicyError as exc:
            raise AppError(str(exc), code="invalid_policy") from exc
        policies = [p for p in policies if p.name != draft["name"]] + [
            engine.ActivePolicy("draft", draft["name"], 0, draft)
        ]
    pre = target.pre
    if agent.status != "active":
        pre = pipeline.Pre("deny", f"agent_{agent.status}", f"The agent is {agent.status}")
    elif bundle.kill_switch.active:
        pre = pipeline.Pre("deny", "kill_switch", "The kill switch is on")
    if pre is not None:
        outcome = engine.Outcome(pre.decision, pre.code, pre.reason)
    else:
        default = bundle.enforcement.default_decision if mode == "audit" else "deny"
        outcome = engine.evaluate(policies, built.granted.grants, built.data, default=default)
    shown = {**built.data, "params": redact_value(req.parameters)}
    return EvaluateResponse(
        decision=outcome.decision,
        reason_code=outcome.reason_code,
        reason=outcome.reason + (f" ({'; '.join(pre.reasons)})" if pre and pre.reasons else ""),
        matched=[m.as_dict() for m in outcome.matched],
        obligations=outcome.obligations,
        risk={
            "level": built.assessment.level,
            "score": built.assessment.score,
            "factors": built.assessment.factors,
        },
        input=shown,
    )
