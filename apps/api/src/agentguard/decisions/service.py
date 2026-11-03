"""Entry points over the pipeline: authorize, execute, redeem a token, scan content.

Every entry point commits once, after the decision and everything it caused (approval,
threats, audit records, counters) is written, then publishes live events.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from agentguard.core import events
from agentguard.core.container import Container
from agentguard.core.errors import AppError
from agentguard.decisions import pipeline
from agentguard.decisions.models import DecisionToken, Run
from agentguard.decisions.outputs import taint_run
from agentguard.decisions.schemas import (
    AuthorizeRequest,
    AuthorizeResponse,
    ExecuteResponse,
    RedeemResponse,
    ScanRequest,
    ScanResponse,
)
from agentguard.identity.service import AgentPrincipal
from agentguard.protection import detectors, injection
from agentguard.threats import service as threats


async def authorize(
    container: Container,
    session: AsyncSession,
    principal: AgentPrincipal,
    req: AuthorizeRequest,
    *,
    ip: str | None,
    source: str = "api",
) -> AuthorizeResponse:
    response, _ = await pipeline.authorize(container, session, principal, req, source=source, ip=ip)
    await events.commit(container, session)
    return response


async def execute(
    container: Container,
    session: AsyncSession,
    principal: AgentPrincipal,
    req: AuthorizeRequest,
    *,
    ip: str | None,
    source: str = "execute",
) -> ExecuteResponse:
    """Decide, and when allowed run the tool through AgentGuard itself."""
    from agentguard.decisions import execute as runner

    response, prepared = await pipeline.authorize(
        container, session, principal, req, source=source, ip=ip
    )
    out = ExecuteResponse(**response.model_dump())
    if not response.allowed or response.would_be not in ("allow", "restrict"):
        prepared.decision.execution = "held" if response.would_be == "require_approval" else "none"
        await events.commit(container, session)
        return out
    try:
        value, meta = await runner.execute(container, session, prepared)
    except AppError as exc:
        prepared.decision.execution = "blocked" if exc.status_code == 403 else "error"
        prepared.decision.execution_meta = {"error": exc.code, "message": exc.message}
        await events.commit(container, session)
        out.result_meta = {"error": exc.code, "message": exc.message}
        return out
    await events.commit(container, session)
    out.executed = True
    out.result = value
    out.result_meta = meta
    return out


async def redeem(
    container: Container,
    session: AsyncSession,
    org_id: uuid.UUID,
    token: str,
    action_hash: str | None,
) -> RedeemResponse:
    """Verify a decision token for the tool that is about to act, and use it up.

    Checks the signature and expiry, that it belongs to the caller's organisation, that the
    verifier's own hash of the action matches (when given), and marks it used atomically:
    a second redemption of the same token fails.
    """
    claims = await container.keys.decode_jwt(
        token,
        typ=pipeline.DECISION_TOKEN_TYP,
        audience=pipeline.DECISION_AUDIENCE,
        issuer=container.settings.public_api_url,
    )
    if claims is None:
        return RedeemResponse(valid=False, reason="invalid_or_expired")
    if claims.get("org") != str(org_id):
        await threats.record(
            session,
            org_id,
            kind="cross_tenant",
            severity="high",
            rule="foreign_decision_token",
            summary="A decision token of another organisation was presented",
            details={"jti": claims.get("jti")},
            dedupe="foreign_token",
            respond=False,
        )
        await session.commit()
        return RedeemResponse(valid=False, reason="invalid_or_expired")
    if action_hash is not None and action_hash != claims.get("ah"):
        return RedeemResponse(valid=False, reason="action_mismatch")
    used = await session.execute(
        update(DecisionToken)
        .where(
            DecisionToken.jti == str(claims["jti"]),
            DecisionToken.org_id == org_id,
            DecisionToken.used_at.is_(None),
            DecisionToken.expires_at > datetime.now(UTC),
        )
        .values(used_at=datetime.now(UTC))
        .returning(DecisionToken.decision_id)
    )
    decision_id = used.scalar()
    await session.commit()
    if decision_id is None:
        return RedeemResponse(valid=False, reason="already_used")
    return RedeemResponse(
        valid=True,
        reason="ok",
        decision_id=decision_id,
        agent=str(claims.get("agent")),
        tool=str(claims.get("tool")),
        action=str(claims.get("act")),
        resource=str(claims.get("res")),
        obligations=dict(claims.get("obl") or {}),
    )


async def scan(
    container: Container, session: AsyncSession, principal: AgentPrincipal, req: ScanRequest
) -> ScanResponse:
    """Scan untrusted content an agent read; taint its run when it carries instructions."""
    from agentguard.org import service as org_service
    from agentguard.threats.classifier import classify

    agent = principal.agent
    bundle = await org_service.load(session, agent.org_id)
    result = injection.scan(req.content)
    classifier: dict[str, Any] | None = None
    if bundle.detection.ai_provider != "none":
        classifier = await classify(container, bundle, req.content)
        if (
            classifier.get("injection")
            and classifier.get("confidence", 0) >= 0.7
            and result.verdict != "injection"
        ):
            # The classifier may raise the verdict, never lower it.
            result.verdict = "injection"
            result.signals.append(
                {
                    "signal": "ai_classifier",
                    "weight": classifier.get("confidence"),
                    "excerpt": classifier.get("reason", "")[:160],
                }
            )
    findings = detectors.scan_text(req.content)
    run: Run | None = None
    if req.run_id:
        run, _ = await pipeline.upsert_run(session, agent, req.run_id, None)
        run.tool_calls -= 1  # a scan is not a tool call
    taint = result.verdict == "injection" or (
        bundle.detection.taint_on == "suspicious" and result.verdict == "suspicious"
    )
    tainted = False
    if taint:
        tainted = await taint_run(
            session, run, source=req.source, verdict=result.verdict, score=result.score
        )
        await threats.record(
            session,
            agent.org_id,
            kind="prompt_injection",
            severity="high" if result.verdict == "injection" else "medium",
            rule="content_scan",
            summary=f"Content {agent.slug} read from {req.source} tried to instruct it",
            agent_id=agent.id,
            run_id=run.id if run else None,
            details=result.as_dict(),
            detector="ai" if classifier and classifier.get("injection") else "rule",
            dedupe=req.source[:80],
        )
    await events.commit(container, session)
    return ScanResponse(
        verdict=result.verdict,
        score=round(result.score, 3),
        signals=result.signals,
        data_classes=detectors.data_classes(findings),
        findings=[f.as_dict() for f in findings[:50]],
        tainted_run=tainted or bool(run and run.tainted_at),
        classifier=classifier,
        content=injection.spotlight(req.content, req.source) if req.spotlight else None,
    )
