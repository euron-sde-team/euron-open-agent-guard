"""Incidents: list, open, investigate, contain, resolve, export."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from agentguard.audit.service import audit
from agentguard.auth.dependencies import StaffRead, StaffWrite
from agentguard.core.deps import ContainerDep, SessionDep
from agentguard.core.events import commit
from agentguard.incidents import service
from agentguard.incidents.models import SEVERITIES, Incident, IncidentEvent, IncidentEvidence

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])


class IncidentIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(..., min_length=3, max_length=200)
    severity: str = Field(..., pattern="^(" + "|".join(SEVERITIES) + ")$")
    summary: str = Field("", max_length=20_000)
    agent_ids: list[uuid.UUID] = Field(default_factory=list, max_length=50)


class IncidentUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str | None = Field(None, min_length=3, max_length=200)
    severity: str | None = Field(None, pattern="^(" + "|".join(SEVERITIES) + ")$")
    summary: str | None = Field(None, max_length=20_000)
    assignee_id: uuid.UUID | None = None


class NoteIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(..., min_length=1, max_length=2000)


class EvidenceIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: str = Field(..., pattern="^(decision|threat|audit)$")
    ref_id: str = Field(..., min_length=1, max_length=64)


class ContainIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: str = Field(
        ...,
        pattern="^(suspend_agent|quarantine_agent|revoke_credentials|revoke_secret|kill_switch)$",
    )
    target: str | None = Field(None, max_length=64)
    reason: str = Field("", max_length=500)


class ResolveIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    root_cause: str = Field(..., min_length=1, max_length=20_000)
    resolution: str = Field(..., min_length=1, max_length=20_000)


class IncidentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    number: int
    title: str
    severity: str
    status: str
    summary: str
    root_cause: str
    resolution: str
    agent_ids: list[str]
    opened_by: str
    assignee_id: uuid.UUID | None
    created_at: datetime
    contained_at: datetime | None
    resolved_at: datetime | None


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    at: datetime
    kind: str
    actor: str
    text: str
    ref_type: str | None
    ref_id: str | None


class EvidenceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    kind: str
    ref_id: str
    title: str
    sha256: str
    added_by: str
    added_at: datetime
    snapshot: dict[str, Any]


class IncidentDetail(IncidentOut):
    timeline: list[EventOut]
    evidence: list[EvidenceOut]


@router.get("", response_model=list[IncidentOut], summary="Incidents, open first")
async def list_incidents(
    actor: StaffRead,
    session: SessionDep,
    status: str | None = Query(None, pattern="^(open|contained|resolved)$"),
) -> list[Incident]:
    stmt = select(Incident).where(Incident.org_id == actor.org_id)
    if status:
        stmt = stmt.where(Incident.status == status)
    return list(
        (
            await session.scalars(
                stmt.order_by(Incident.status == "resolved", Incident.created_at.desc()).limit(500)
            )
        ).all()
    )


@router.post("", response_model=IncidentDetail, status_code=201, summary="Open an incident")
async def create(
    body: IncidentIn, actor: StaffWrite, container: ContainerDep, session: SessionDep
) -> IncidentDetail:
    incident = await service.create(
        session,
        actor,
        title=body.title,
        severity=body.severity,
        summary=body.summary,
        agent_ids=body.agent_ids,
    )
    await commit(container, session)
    return await get(incident.id, actor, session)


@router.get(
    "/{incident_id}",
    response_model=IncidentDetail,
    summary="One incident with its timeline and evidence",
)
async def get(incident_id: uuid.UUID, actor: StaffRead, session: SessionDep) -> IncidentDetail:
    incident = await service.get(session, actor.org_id, incident_id)
    timeline = (
        await session.scalars(
            select(IncidentEvent)
            .where(IncidentEvent.incident_id == incident.id)
            .order_by(IncidentEvent.id)
        )
    ).all()
    evidence = (
        await session.scalars(
            select(IncidentEvidence)
            .where(IncidentEvidence.incident_id == incident.id)
            .order_by(IncidentEvidence.added_at)
        )
    ).all()
    return IncidentDetail(
        **IncidentOut.model_validate(incident).model_dump(),
        timeline=[EventOut.model_validate(e) for e in timeline],
        evidence=[EvidenceOut.model_validate(e) for e in evidence],
    )


@router.patch("/{incident_id}", response_model=IncidentDetail, summary="Change an incident")
async def update(
    incident_id: uuid.UUID,
    body: IncidentUpdate,
    actor: StaffWrite,
    container: ContainerDep,
    session: SessionDep,
) -> IncidentDetail:
    incident = await service.get(session, actor.org_id, incident_id)
    changes = body.model_dump(exclude_unset=True)
    for key, value in changes.items():
        setattr(incident, key, value)
    if changes:
        service.add_event(
            session, incident, "updated", actor.label, f"Changed {', '.join(sorted(changes))}"
        )
        audit(session, actor, "incident.updated", "incident", incident.id, fields=sorted(changes))
    await commit(container, session)
    return await get(incident_id, actor, session)


@router.post(
    "/{incident_id}/notes", response_model=IncidentDetail, summary="Add a note to the timeline"
)
async def note(
    incident_id: uuid.UUID,
    body: NoteIn,
    actor: StaffWrite,
    container: ContainerDep,
    session: SessionDep,
) -> IncidentDetail:
    incident = await service.get(session, actor.org_id, incident_id)
    await service.note(session, actor, incident, body.text)
    await commit(container, session)
    return await get(incident_id, actor, session)


@router.post(
    "/{incident_id}/evidence",
    response_model=IncidentDetail,
    summary="Freeze a decision, threat or audit record as evidence",
)
async def evidence(
    incident_id: uuid.UUID,
    body: EvidenceIn,
    actor: StaffWrite,
    container: ContainerDep,
    session: SessionDep,
) -> IncidentDetail:
    incident = await service.get(session, actor.org_id, incident_id)
    await service.add_evidence(session, actor, incident, body.kind, body.ref_id)
    await commit(container, session)
    return await get(incident_id, actor, session)


@router.post(
    "/{incident_id}/contain",
    response_model=IncidentDetail,
    summary="Containment: suspend, quarantine, revoke credentials or a secret, kill switch",
)
async def contain(
    incident_id: uuid.UUID,
    body: ContainIn,
    actor: StaffWrite,
    container: ContainerDep,
    session: SessionDep,
) -> IncidentDetail:
    incident = await service.get(session, actor.org_id, incident_id)
    await service.contain(session, actor, incident, body.action, body.target, body.reason)
    await commit(container, session)
    return await get(incident_id, actor, session)


@router.post(
    "/{incident_id}/resolve",
    response_model=IncidentDetail,
    summary="Close the incident with its root cause",
)
async def resolve(
    incident_id: uuid.UUID,
    body: ResolveIn,
    actor: StaffWrite,
    container: ContainerDep,
    session: SessionDep,
) -> IncidentDetail:
    incident = await service.get(session, actor.org_id, incident_id)
    await service.resolve(session, actor, incident, body.root_cause, body.resolution)
    await commit(container, session)
    return await get(incident_id, actor, session)


@router.get("/{incident_id}/export", summary="The incident report as Markdown or JSON")
async def export(
    incident_id: uuid.UUID,
    actor: StaffRead,
    session: SessionDep,
    fmt: str = Query("md", alias="format", pattern="^(md|json)$"),
) -> Any:
    incident = await service.get(session, actor.org_id, incident_id)
    report = await service.export(session, incident)
    filename = f"INC-{incident.number}"
    if fmt == "json":
        return JSONResponse(
            report, headers={"content-disposition": f'attachment; filename="{filename}.json"'}
        )
    return PlainTextResponse(
        service.to_markdown(report),
        media_type="text/markdown",
        headers={"content-disposition": f'attachment; filename="{filename}.md"'},
    )
