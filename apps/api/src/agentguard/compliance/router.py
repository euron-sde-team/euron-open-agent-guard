"""The compliance report, and the security overview behind the dashboard's first page."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel
from sqlalchemy import func, select

from agentguard.approvals.models import ApprovalRequest
from agentguard.auth.dependencies import StaffRead
from agentguard.compliance import service
from agentguard.core.deps import ContainerDep, SessionDep
from agentguard.decisions.models import Decision
from agentguard.identity.models import Agent
from agentguard.incidents.models import Incident
from agentguard.network.models import EgressEvent
from agentguard.org import service as org_service
from agentguard.threats.models import ThreatEvent

router = APIRouter(prefix="/api/v1", tags=["compliance and overview"])


@router.get("/compliance/report", summary="OWASP agentic Top 10: live evidence per risk, signed")
async def report(actor: StaffRead, container: ContainerDep, session: SessionDep) -> dict[str, Any]:
    return await service.build(container, session, actor.org_id)


@router.get("/compliance/export", summary="The compliance report as Markdown or JSON")
async def export(
    actor: StaffRead,
    container: ContainerDep,
    session: SessionDep,
    fmt: str = Query("md", alias="format", pattern="^(md|json)$"),
) -> Any:
    data = await service.build(container, session, actor.org_id)
    if fmt == "json":
        return JSONResponse(
            data,
            headers={"content-disposition": 'attachment; filename="agentguard-compliance.json"'},
        )
    return PlainTextResponse(
        service.to_markdown(data),
        media_type="text/markdown",
        headers={"content-disposition": 'attachment; filename="agentguard-compliance.md"'},
    )


class DayCounts(BaseModel):
    day: str
    allow: int = 0
    restrict: int = 0
    require_approval: int = 0
    deny: int = 0
    quarantine: int = 0


class DeniedTool(BaseModel):
    tool: str
    denied: int


class RiskyAgent(BaseModel):
    agent: str
    agent_id: str
    risk: float
    actions: int


class RecentThreat(BaseModel):
    id: str
    at: str
    kind: str
    severity: str
    summary: str
    agent: str | None
    status: str


class Overview(BaseModel):
    kill_switch: dict[str, Any]
    mode: str
    agents: dict[str, int]
    decisions_24h: dict[str, int]
    decisions_by_day: list[DayCounts]
    approvals_pending: int
    threats_open: dict[str, int]
    incidents_open: int
    incidents_contained: int
    blocked_connections_24h: int
    top_denied_tools: list[DeniedTool]
    top_risky_agents: list[RiskyAgent]
    latency_ms: dict[str, float]
    recent_threats: list[RecentThreat]


@router.get(
    "/security/metrics",
    response_model=Overview,
    summary="Security health and activity for the overview page",
)
async def overview(
    actor: StaffRead, session: SessionDep, days: int = Query(14, ge=1, le=90)
) -> Overview:
    org_id = actor.org_id
    now = datetime.now(UTC)
    day_ago = now - timedelta(hours=24)
    since = now - timedelta(days=days)
    bundle = await org_service.load(session, org_id)
    agents = dict(
        (
            await session.execute(
                select(Agent.status, func.count())
                .where(Agent.org_id == org_id)
                .group_by(Agent.status)
            )
        ).all()
    )
    decided = dict(
        (
            await session.execute(
                select(Decision.would_be, func.count())
                .where(Decision.org_id == org_id, Decision.at >= day_ago)
                .group_by(Decision.would_be)
            )
        ).all()
    )
    day = func.date_trunc("day", Decision.at)
    by_day: dict[str, dict[str, Any]] = {}
    for d, outcome, count in (
        await session.execute(
            select(day, Decision.would_be, func.count())
            .where(Decision.org_id == org_id, Decision.at >= since)
            .group_by(day, Decision.would_be)
            .order_by(day)
        )
    ).all():
        key = d.date().isoformat()
        by_day.setdefault(
            key,
            {
                "day": key,
                "allow": 0,
                "restrict": 0,
                "require_approval": 0,
                "deny": 0,
                "quarantine": 0,
            },
        )[outcome] = int(count)
    series = []
    for i in range(days - 1, -1, -1):
        key = (now - timedelta(days=i)).date().isoformat()
        series.append(
            by_day.get(
                key,
                {
                    "day": key,
                    "allow": 0,
                    "restrict": 0,
                    "require_approval": 0,
                    "deny": 0,
                    "quarantine": 0,
                },
            )
        )
    pending = await session.scalar(
        select(func.count())
        .select_from(ApprovalRequest)
        .where(ApprovalRequest.org_id == org_id, ApprovalRequest.status == "pending")
    )
    threats = dict(
        (
            await session.execute(
                select(ThreatEvent.severity, func.count())
                .where(ThreatEvent.org_id == org_id, ThreatEvent.status == "open")
                .group_by(ThreatEvent.severity)
            )
        ).all()
    )
    incidents = dict(
        (
            await session.execute(
                select(Incident.status, func.count())
                .where(Incident.org_id == org_id)
                .group_by(Incident.status)
            )
        ).all()
    )
    blocked = await session.scalar(
        select(func.count())
        .select_from(EgressEvent)
        .where(
            EgressEvent.org_id == org_id, EgressEvent.at >= day_ago, EgressEvent.decision == "deny"
        )
    )
    week = now - timedelta(days=7)
    top_tools = [
        {"tool": t, "denied": int(c)}
        for t, c in (
            await session.execute(
                select(Decision.tool, func.count())
                .where(
                    Decision.org_id == org_id,
                    Decision.at >= week,
                    Decision.would_be.in_(("deny", "quarantine")),
                )
                .group_by(Decision.tool)
                .order_by(func.count().desc())
                .limit(6)
            )
        ).all()
    ]
    names = dict(
        (await session.execute(select(Agent.id, Agent.slug).where(Agent.org_id == org_id))).all()
    )
    risky = [
        {
            "agent": names.get(a, "?"),
            "agent_id": str(a),
            "risk": round(float(score), 1),
            "actions": int(n),
        }
        for a, score, n in (
            await session.execute(
                select(Decision.agent_id, func.avg(Decision.risk_score), func.count())
                .where(
                    Decision.org_id == org_id, Decision.at >= week, Decision.agent_id.is_not(None)
                )
                .group_by(Decision.agent_id)
                .order_by(func.avg(Decision.risk_score).desc())
                .limit(6)
            )
        ).all()
    ]
    p50, p95 = (
        await session.execute(
            select(
                func.percentile_cont(0.5).within_group(Decision.latency_ms),
                func.percentile_cont(0.95).within_group(Decision.latency_ms),
            ).where(
                Decision.org_id == org_id,
                Decision.at >= day_ago,
                Decision.source.in_(("api", "execute", "mcp")),
            )
        )
    ).one()
    recent = [
        {
            "id": str(t.id),
            "at": t.last_seen_at.isoformat(),
            "kind": t.kind,
            "severity": t.severity,
            "summary": t.summary,
            "agent": names.get(t.agent_id) if t.agent_id else None,
            "status": t.status,
        }
        for t in (
            await session.scalars(
                select(ThreatEvent)
                .where(ThreatEvent.org_id == org_id)
                .order_by(ThreatEvent.last_seen_at.desc())
                .limit(8)
            )
        ).all()
    ]
    return Overview(
        kill_switch=bundle.kill_switch.model_dump(mode="json"),
        mode=bundle.enforcement.mode,
        agents={k: int(v) for k, v in agents.items()},
        decisions_24h={k: int(v) for k, v in decided.items()},
        decisions_by_day=series,
        approvals_pending=int(pending or 0),
        threats_open={k: int(v) for k, v in threats.items()},
        incidents_open=int(incidents.get("open", 0)),
        incidents_contained=int(incidents.get("contained", 0)),
        blocked_connections_24h=int(blocked or 0),
        top_denied_tools=top_tools,
        top_risky_agents=risky,
        latency_ms={"p50": round(float(p50 or 0), 2), "p95": round(float(p95 or 0), 2)},
        recent_threats=recent,
    )
