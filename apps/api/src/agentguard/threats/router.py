"""Threats, the security event timeline, a content analyser, risk rules and assessments, and
sandbox sessions."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Query, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from agentguard.audit.service import audit
from agentguard.auth.dependencies import StaffRead, StaffWrite
from agentguard.core.deps import ContainerDep, SessionDep
from agentguard.core.errors import AppError, ConflictError, NotFoundError
from agentguard.decisions.models import Decision
from agentguard.identity.models import Agent
from agentguard.network.models import EgressEvent
from agentguard.policies import expr
from agentguard.policies.service import bump
from agentguard.protection import detectors, injection
from agentguard.risk.models import RiskRule
from agentguard.sandbox.models import SandboxSession
from agentguard.threats import service
from agentguard.threats.models import ThreatEvent

router = APIRouter(prefix="/api/v1", tags=["threats and risk"])


class ThreatOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    at: datetime
    last_seen_at: datetime
    agent_id: uuid.UUID | None
    agent: str | None = None
    run_id: uuid.UUID | None
    decision_id: uuid.UUID | None
    kind: str
    severity: str
    detector: str
    rule: str
    summary: str
    details: dict[str, Any]
    occurrences: int
    status: str
    responses: list[Any]
    incident_id: uuid.UUID | None


class ThreatUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: str = Field(..., pattern="^(open|acknowledged|resolved|false_positive)$")


class AnalyzeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    content: str = Field(..., max_length=500_000)


class AnalyzeOut(BaseModel):
    verdict: str
    score: float
    signals: list[dict[str, Any]]
    hidden_characters: int
    decoded_segments: int
    findings: list[dict[str, Any]]
    data_classes: list[str]
    redacted: str


class SecurityEvent(BaseModel):
    at: datetime
    kind: str
    severity: str
    title: str
    agent: str | None = None
    ref_type: str
    ref_id: str


class RiskRuleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(..., min_length=1, max_length=120)
    condition: str = Field(..., min_length=1, max_length=1000)
    points: int = Field(..., ge=-100, le=100)
    enabled: bool = True


class RiskRuleOut(RiskRuleIn):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    created_at: datetime


class AssessmentOut(BaseModel):
    decision_id: uuid.UUID
    at: datetime
    agent: str | None
    tool: str
    action: str
    resource: str
    risk_level: str
    risk_score: int
    factors: list[Any]
    decision: str


class SandboxOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    agent_id: uuid.UUID | None
    agent: str | None = None
    run_id: uuid.UUID | None
    decision_id: uuid.UUID | None
    tool: str
    language: str
    network: str
    limits: dict[str, Any]
    code_sha256: str
    code_bytes: int
    verdict: str
    exit_code: int | None
    signal: int | None
    cpu_ms: int
    wall_ms: int
    memory_kb: int
    stdout_bytes: int
    stderr_bytes: int
    started_at: datetime
    ended_at: datetime | None


async def _names(session: SessionDep, org_id: uuid.UUID) -> dict[uuid.UUID, str]:
    return dict(
        (await session.execute(select(Agent.id, Agent.slug).where(Agent.org_id == org_id))).all()
    )


@router.get("/threats", response_model=list[ThreatOut], summary="Detected threats, newest first")
async def list_threats(
    actor: StaffRead,
    session: SessionDep,
    status: str | None = Query(None, pattern="^(open|acknowledged|resolved|false_positive)$"),
    severity: str | None = Query(None, pattern="^(low|medium|high|critical)$"),
    kind: str | None = Query(None, max_length=32),
    agent_id: uuid.UUID | None = None,
    limit: int = Query(200, ge=1, le=1000),
) -> list[ThreatOut]:
    stmt = select(ThreatEvent).where(ThreatEvent.org_id == actor.org_id)
    if status:
        stmt = stmt.where(ThreatEvent.status == status)
    if severity:
        stmt = stmt.where(ThreatEvent.severity == severity)
    if kind:
        stmt = stmt.where(ThreatEvent.kind == kind)
    if agent_id:
        stmt = stmt.where(ThreatEvent.agent_id == agent_id)
    rows = (
        await session.scalars(stmt.order_by(ThreatEvent.last_seen_at.desc()).limit(limit))
    ).all()
    names = await _names(session, actor.org_id)
    out = []
    for r in rows:
        item = ThreatOut.model_validate(r)
        item.agent = names.get(r.agent_id) if r.agent_id else None
        out.append(item)
    return out


@router.get("/threats/{threat_id}", response_model=ThreatOut, summary="One threat")
async def get_threat(threat_id: uuid.UUID, actor: StaffRead, session: SessionDep) -> ThreatOut:
    row = await session.get(ThreatEvent, threat_id)
    if row is None or row.org_id != actor.org_id:
        raise NotFoundError("Threat not found")
    item = ThreatOut.model_validate(row)
    item.agent = (await _names(session, actor.org_id)).get(row.agent_id) if row.agent_id else None
    return item


@router.patch(
    "/threats/{threat_id}",
    response_model=ThreatOut,
    summary="Acknowledge, resolve or dismiss a threat",
)
async def update_threat(
    threat_id: uuid.UUID, body: ThreatUpdate, actor: StaffWrite, session: SessionDep
) -> ThreatOut:
    row = await service.set_status(session, actor.org_id, threat_id, body.status)
    if row is None:
        raise NotFoundError("Threat not found")
    audit(session, actor, "threat.status", "threat", threat_id, status=body.status)
    await session.commit()
    return await get_threat(threat_id, actor, session)


@router.post(
    "/threats/analyze",
    response_model=AnalyzeOut,
    summary="Check a piece of content for injection, personal data and credentials (nothing recorded)",
)
async def analyze(body: AnalyzeIn, actor: StaffRead) -> AnalyzeOut:
    result = injection.scan(body.content)
    findings = detectors.scan_text(body.content)
    return AnalyzeOut(
        verdict=result.verdict,
        score=round(result.score, 3),
        signals=result.signals,
        hidden_characters=result.hidden_characters,
        decoded_segments=result.decoded_segments,
        findings=[{**f.as_dict(), "start": f.start, "end": f.end} for f in findings[:200]],
        data_classes=detectors.data_classes(findings),
        redacted=detectors.redact_text(body.content, findings),
    )


@router.get(
    "/security-events",
    response_model=list[SecurityEvent],
    summary="One timeline: threats, denied actions and blocked connections",
)
async def security_events(
    actor: StaffRead,
    session: SessionDep,
    hours: int = Query(24, ge=1, le=24 * 30),
    limit: int = Query(100, ge=1, le=500),
) -> list[SecurityEvent]:
    since = datetime.now(UTC) - timedelta(hours=hours)
    names = await _names(session, actor.org_id)
    events: list[SecurityEvent] = []
    for t in (
        await session.scalars(
            select(ThreatEvent)
            .where(ThreatEvent.org_id == actor.org_id, ThreatEvent.last_seen_at >= since)
            .order_by(ThreatEvent.last_seen_at.desc())
            .limit(limit)
        )
    ).all():
        events.append(
            SecurityEvent(
                at=t.last_seen_at,
                kind=f"threat.{t.kind}",
                severity=t.severity,
                title=t.summary,
                agent=names.get(t.agent_id) if t.agent_id else None,
                ref_type="threat",
                ref_id=str(t.id),
            )
        )
    for d in (
        await session.scalars(
            select(Decision)
            .where(
                Decision.org_id == actor.org_id,
                Decision.at >= since,
                Decision.would_be.in_(("deny", "quarantine")),
            )
            .order_by(Decision.at.desc())
            .limit(limit)
        )
    ).all():
        events.append(
            SecurityEvent(
                at=d.at,
                kind=f"decision.{d.would_be}",
                severity="high"
                if d.would_be == "quarantine"
                else "medium"
                if d.risk_level in ("high", "critical")
                else "low",
                title=f"{d.tool}.{d.action} denied: {d.reason_code}",
                agent=names.get(d.agent_id) if d.agent_id else None,
                ref_type="decision",
                ref_id=str(d.id),
            )
        )
    for e in (
        await session.scalars(
            select(EgressEvent)
            .where(
                EgressEvent.org_id == actor.org_id,
                EgressEvent.at >= since,
                EgressEvent.decision == "deny",
            )
            .order_by(EgressEvent.id.desc())
            .limit(limit)
        )
    ).all():
        events.append(
            SecurityEvent(
                at=e.at,
                kind="network.blocked",
                severity="low",
                title=f"Blocked {e.host}:{e.port} ({e.reason})",
                agent=names.get(e.agent_id) if e.agent_id else None,
                ref_type="egress",
                ref_id=str(e.id),
            )
        )
    return sorted(events, key=lambda e: e.at, reverse=True)[:limit]


@router.get(
    "/risk-assessments",
    response_model=list[AssessmentOut],
    summary="Recent actions by risk, highest first",
)
async def risk_assessments(
    actor: StaffRead,
    session: SessionDep,
    level: str | None = Query(None, pattern="^(low|medium|high|critical)$"),
    hours: int = Query(24, ge=1, le=24 * 30),
    limit: int = Query(100, ge=1, le=500),
) -> list[AssessmentOut]:
    since = datetime.now(UTC) - timedelta(hours=hours)
    stmt = select(Decision).where(Decision.org_id == actor.org_id, Decision.at >= since)
    if level:
        stmt = stmt.where(Decision.risk_level == level)
    rows = (
        await session.scalars(
            stmt.order_by(Decision.risk_score.desc(), Decision.at.desc()).limit(limit)
        )
    ).all()
    names = await _names(session, actor.org_id)
    return [
        AssessmentOut(
            decision_id=r.id,
            at=r.at,
            agent=names.get(r.agent_id) if r.agent_id else None,
            tool=r.tool,
            action=r.action,
            resource=r.resource,
            risk_level=r.risk_level,
            risk_score=r.risk_score,
            factors=r.risk_factors,
            decision=r.would_be,
        )
        for r in rows
    ]


def _check_condition(condition: str) -> None:
    try:
        expr.parse(condition)
    except expr.ExprError as exc:
        raise AppError(str(exc), code="invalid_condition") from exc


@router.get("/risk-rules", response_model=list[RiskRuleOut], summary="Organisation risk rules")
async def list_rules(actor: StaffRead, session: SessionDep) -> list[RiskRule]:
    return list(
        (
            await session.scalars(
                select(RiskRule).where(RiskRule.org_id == actor.org_id).order_by(RiskRule.name)
            )
        ).all()
    )


@router.post("/risk-rules", response_model=RiskRuleOut, status_code=201, summary="Add a risk rule")
async def create_rule(
    body: RiskRuleIn, actor: StaffWrite, container: ContainerDep, session: SessionDep
) -> RiskRule:
    _check_condition(body.condition)
    if await session.scalar(
        select(RiskRule.id).where(RiskRule.org_id == actor.org_id, RiskRule.name == body.name)
    ):
        raise ConflictError(f"A rule named {body.name} exists", code="duplicate")
    row = RiskRule(org_id=actor.org_id, **body.model_dump())
    session.add(row)
    await session.flush()
    await bump(container, actor.org_id)
    audit(
        session, actor, "risk_rule.created", "risk_rule", row.id, name=row.name, points=row.points
    )
    await session.commit()
    return row


@router.put("/risk-rules/{rule_id}", response_model=RiskRuleOut, summary="Change a risk rule")
async def update_rule(
    rule_id: uuid.UUID,
    body: RiskRuleIn,
    actor: StaffWrite,
    container: ContainerDep,
    session: SessionDep,
) -> RiskRule:
    _check_condition(body.condition)
    row = await session.get(RiskRule, rule_id)
    if row is None or row.org_id != actor.org_id:
        raise NotFoundError("Risk rule not found")
    for key, value in body.model_dump().items():
        setattr(row, key, value)
    await bump(container, actor.org_id)
    audit(session, actor, "risk_rule.updated", "risk_rule", row.id)
    await session.commit()
    return row


@router.delete("/risk-rules/{rule_id}", status_code=204, summary="Remove a risk rule")
async def delete_rule(
    rule_id: uuid.UUID, actor: StaffWrite, container: ContainerDep, session: SessionDep
) -> Response:
    row = await session.get(RiskRule, rule_id)
    if row is None or row.org_id != actor.org_id:
        raise NotFoundError("Risk rule not found")
    await bump(container, actor.org_id)
    audit(session, actor, "risk_rule.deleted", "risk_rule", row.id)
    await session.delete(row)
    await session.commit()
    return Response(status_code=204)


@router.get(
    "/sandbox/sessions",
    response_model=list[SandboxOut],
    summary="Code runs in the sandbox, newest first",
)
async def sandbox_sessions(
    actor: StaffRead,
    session: SessionDep,
    verdict: str | None = Query(None, max_length=16),
    limit: int = Query(200, ge=1, le=1000),
) -> list[SandboxOut]:
    stmt = select(SandboxSession).where(SandboxSession.org_id == actor.org_id)
    if verdict:
        stmt = stmt.where(SandboxSession.verdict == verdict)
    rows = (
        await session.scalars(stmt.order_by(SandboxSession.started_at.desc()).limit(limit))
    ).all()
    names = await _names(session, actor.org_id)
    out = []
    for r in rows:
        item = SandboxOut.model_validate(r)
        item.agent = names.get(r.agent_id) if r.agent_id else None
        out.append(item)
    return out


class SandboxHealth(BaseModel):
    reachable: bool
    detail: str


@router.get(
    "/sandbox/health", response_model=SandboxHealth, summary="Whether the sandbox service answers"
)
async def sandbox_health(actor: StaffRead, container: ContainerDep) -> SandboxHealth:
    try:
        resp = await container.http.get(
            f"{container.settings.sandbox_url.rstrip('/')}/healthz", timeout=3.0
        )
    except Exception as exc:
        return SandboxHealth(reachable=False, detail=type(exc).__name__)
    return SandboxHealth(reachable=resp.status_code == 200, detail=f"HTTP {resp.status_code}")
