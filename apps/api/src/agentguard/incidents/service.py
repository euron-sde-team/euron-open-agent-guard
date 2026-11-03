"""Incidents: open, investigate, contain, resolve, export.

An incident collects what matters about one security event: a timeline (detections,
decisions, containment actions and notes, in order), frozen evidence (snapshots of
decisions, threats and audit records, each hashed so the export proves it was not edited),
and the containment actions taken from it: suspend or quarantine agents, revoke their
credentials, revoke a secret, switch on the organisation's kill switch.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from typing import Any

import orjson
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from agentguard.audit.service import Actor, audit
from agentguard.core import events
from agentguard.core.canonical import canonical_json
from agentguard.core.errors import AppError, NotFoundError
from agentguard.incidents.models import SEVERITIES, Incident, IncidentEvent, IncidentEvidence
from agentguard.org.models import Org
from agentguard.threats.models import ThreatEvent


def _now() -> datetime:
    return datetime.now(UTC)


async def _next_number(session: AsyncSession, org_id: uuid.UUID) -> int:
    number = await session.scalar(
        update(Org)
        .where(Org.id == org_id)
        .values(incident_seq=Org.incident_seq + 1)
        .returning(Org.incident_seq)
    )
    assert number is not None
    return int(number)


def add_event(
    session: AsyncSession,
    incident: Incident,
    kind: str,
    actor: str,
    text: str,
    ref_type: str | None = None,
    ref_id: object | None = None,
) -> None:
    session.add(
        IncidentEvent(
            org_id=incident.org_id,
            incident_id=incident.id,
            kind=kind,
            actor=actor,
            text=text[:2000],
            ref_type=ref_type,
            ref_id=str(ref_id) if ref_id is not None else None,
        )
    )


async def create(
    session: AsyncSession,
    actor: Actor,
    *,
    title: str,
    severity: str,
    summary: str = "",
    agent_ids: list[uuid.UUID] | None = None,
) -> Incident:
    if severity not in SEVERITIES:
        raise AppError(f"Severity is one of {', '.join(SEVERITIES)}", code="invalid_severity")
    incident = Incident(
        org_id=actor.org_id,
        number=await _next_number(session, actor.org_id),
        title=title[:200],
        severity=severity,
        summary=summary,
        agent_ids=[str(a) for a in agent_ids or []],
        opened_by=actor.label,
    )
    session.add(incident)
    await session.flush()
    add_event(session, incident, "opened", actor.label, f"Incident opened: {incident.title}")
    audit(
        session,
        actor,
        "incident.opened",
        "incident",
        incident.id,
        number=incident.number,
        severity=severity,
    )
    await _announce(session, incident, "incident.opened")
    return incident


async def _announce(session: AsyncSession, incident: Incident, event: str) -> None:
    from agentguard.integrations.service import dispatch

    events.emit(session, f"org:{incident.org_id}", {"type": "incident", "id": str(incident.id)})
    await dispatch(
        session,
        incident.org_id,
        event,
        {
            "id": str(incident.id),
            "number": incident.number,
            "title": incident.title,
            "severity": incident.severity,
            "status": incident.status,
        },
    )


async def open_from_threat(session: AsyncSession, threat: ThreatEvent) -> Incident:
    from agentguard.audit.service import system_actor

    actor = system_actor(threat.org_id, "threat-response")
    incident = await create(
        session,
        actor,
        title=f"{threat.kind.replace('_', ' ').capitalize()}: {threat.summary}"[:200],
        severity=threat.severity,
        summary=f"Opened automatically by the {threat.rule} detection.",
        agent_ids=[threat.agent_id] if threat.agent_id else [],
    )
    add_event(
        session, incident, "detection", "threat-detection", threat.summary, "threat", threat.id
    )
    await add_evidence(session, actor, incident, "threat", str(threat.id))
    if threat.decision_id is not None:
        await add_evidence(session, actor, incident, "decision", str(threat.decision_id))
    return incident


async def get(session: AsyncSession, org_id: uuid.UUID, incident_id: uuid.UUID) -> Incident:
    incident = await session.get(Incident, incident_id)
    if incident is None or incident.org_id != org_id:
        raise NotFoundError("Incident not found")
    return incident


async def _snapshot(
    session: AsyncSession, org_id: uuid.UUID, kind: str, ref_id: str
) -> tuple[str, dict[str, Any]]:
    from agentguard.audit.models import AuditLog
    from agentguard.decisions.models import Decision

    def plain(row: Any) -> dict[str, Any]:
        out: dict[str, Any] = orjson.loads(
            orjson.dumps({c.key: getattr(row, c.key) for c in row.__table__.columns}, default=str)
        )
        return out

    if kind == "decision":
        row = await session.get(Decision, uuid.UUID(ref_id))
        if row is None or row.org_id != org_id:
            raise NotFoundError("Decision not found")
        return f"Decision {row.decision} for {row.tool}.{row.action}", plain(row)
    if kind == "threat":
        threat = await session.get(ThreatEvent, uuid.UUID(ref_id))
        if threat is None or threat.org_id != org_id:
            raise NotFoundError("Threat not found")
        return f"Threat: {threat.summary}", plain(threat)
    if kind == "audit":
        entry = await session.scalar(
            select(AuditLog).where(AuditLog.org_id == org_id, AuditLog.id == int(ref_id))
        )
        if entry is None:
            raise NotFoundError("Audit record not found")
        return f"Audit #{entry.seq or entry.id}: {entry.action}", plain(entry)
    raise AppError("Evidence kind is decision, threat or audit", code="invalid_kind")


async def add_evidence(
    session: AsyncSession, actor: Actor, incident: Incident, kind: str, ref_id: str
) -> IncidentEvidence:
    title, snapshot = await _snapshot(session, incident.org_id, kind, ref_id)
    evidence = IncidentEvidence(
        org_id=incident.org_id,
        incident_id=incident.id,
        kind=kind,
        ref_id=ref_id,
        title=title[:300],
        snapshot=snapshot,
        sha256=hashlib.sha256(canonical_json(snapshot)).hexdigest(),
        added_by=actor.label,
    )
    session.add(evidence)
    await session.flush()
    add_event(
        session,
        incident,
        "evidence",
        actor.label,
        f"Evidence added: {evidence.title}",
        kind,
        ref_id,
    )
    return evidence


async def note(session: AsyncSession, actor: Actor, incident: Incident, text: str) -> None:
    add_event(session, incident, "note", actor.label, text)
    audit(session, actor, "incident.note", "incident", incident.id)


async def contain(
    session: AsyncSession,
    actor: Actor,
    incident: Incident,
    action: str,
    target: str | None,
    reason: str,
) -> str:
    """Run a containment action and record it on the timeline."""
    from agentguard.identity import service as identity

    text: str
    if action in ("suspend_agent", "quarantine_agent", "revoke_credentials"):
        if not target:
            raise AppError("Choose an agent", code="target_required")
        agent = await identity.get_agent(session, incident.org_id, uuid.UUID(target))
        if action == "revoke_credentials":
            count = await identity.revoke_all_credentials(session, actor, agent)
            text = f"Revoked {count} credential(s) of {agent.slug}"
        else:
            status = "suspended" if action == "suspend_agent" else "quarantined"
            await identity.set_status(
                session, actor, agent, status, reason or f"INC-{incident.number}"
            )
            text = f"{status.capitalize()} {agent.slug}"
        if str(agent.id) not in incident.agent_ids:
            incident.agent_ids = [*incident.agent_ids, str(agent.id)]
    elif action == "revoke_secret":
        from agentguard.secrets import service as secrets

        if not target:
            raise AppError("Choose a secret", code="target_required")
        secret = await secrets.get_secret(session, incident.org_id, uuid.UUID(target))
        await secrets.revoke_secret(session, actor, secret, reason or f"INC-{incident.number}")
        text = f"Revoked secret {secret.name}"
    elif action == "kill_switch":
        from agentguard.org import service as org

        await org.set_kill_switch(session, actor, True, reason or f"INC-{incident.number}")
        text = "Switched on the organisation kill switch"
    else:
        raise AppError(
            "Action is suspend_agent, quarantine_agent, revoke_credentials, revoke_secret or kill_switch",
            code="invalid_action",
        )
    add_event(session, incident, "containment", actor.label, text)
    if incident.status == "open":
        incident.status = "contained"
        incident.contained_at = _now()
    audit(
        session,
        actor,
        "incident.containment",
        "incident",
        incident.id,
        action=action,
        target=target,
    )
    await _announce(session, incident, "incident.updated")
    return text


async def resolve(
    session: AsyncSession, actor: Actor, incident: Incident, root_cause: str, resolution: str
) -> None:
    if not root_cause.strip() or not resolution.strip():
        raise AppError("Resolving needs a root cause and a resolution", code="incomplete")
    incident.status = "resolved"
    incident.resolved_at = _now()
    incident.root_cause = root_cause
    incident.resolution = resolution
    if incident.contained_at is None:
        incident.contained_at = incident.resolved_at
    add_event(session, incident, "resolved", actor.label, f"Resolved: {resolution[:300]}")
    audit(session, actor, "incident.resolved", "incident", incident.id)
    await _announce(session, incident, "incident.updated")


async def export(session: AsyncSession, incident: Incident) -> dict[str, Any]:
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
    report: dict[str, Any] = {
        "incident": f"INC-{incident.number}",
        "title": incident.title,
        "severity": incident.severity,
        "status": incident.status,
        "opened_at": incident.created_at.isoformat(),
        "opened_by": incident.opened_by,
        "contained_at": incident.contained_at.isoformat() if incident.contained_at else None,
        "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
        "summary": incident.summary,
        "root_cause": incident.root_cause,
        "resolution": incident.resolution,
        "agents": incident.agent_ids,
        "timeline": [
            {
                "at": e.at.isoformat(),
                "kind": e.kind,
                "actor": e.actor,
                "text": e.text,
                "ref": f"{e.ref_type}:{e.ref_id}" if e.ref_type else None,
            }
            for e in timeline
        ],
        "evidence": [
            {
                "kind": ev.kind,
                "ref": ev.ref_id,
                "title": ev.title,
                "sha256": ev.sha256,
                "added_by": ev.added_by,
                "snapshot": ev.snapshot,
            }
            for ev in evidence
        ],
        "exported_at": _now().isoformat(),
    }
    report["sha256"] = hashlib.sha256(
        canonical_json({k: v for k, v in report.items() if k != "exported_at"})
    ).hexdigest()
    return report


def to_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# {report['incident']}: {report['title']}",
        "",
        f"* Severity: {report['severity']}",
        f"* Status: {report['status']}",
        f"* Opened: {report['opened_at']} by {report['opened_by']}",
        f"* Contained: {report['contained_at'] or 'not yet'}",
        f"* Resolved: {report['resolved_at'] or 'not yet'}",
        "",
        "## Summary",
        "",
        report["summary"] or "(none)",
        "",
        "## Root cause",
        "",
        report["root_cause"] or "(not recorded yet)",
        "",
        "## Resolution",
        "",
        report["resolution"] or "(not recorded yet)",
        "",
        "## Timeline",
        "",
        "| Time (UTC) | Kind | Who | What |",
        "| --- | --- | --- | --- |",
    ]
    for e in report["timeline"]:
        text = e["text"].replace("|", "/").replace("\n", " ")
        lines.append(f"| {e['at']} | {e['kind']} | {e['actor']} | {text} |")
    lines += [
        "",
        "## Evidence",
        "",
        "| Kind | Reference | Title | SHA-256 |",
        "| --- | --- | --- | --- |",
    ]
    for ev in report["evidence"]:
        lines.append(
            f"| {ev['kind']} | {ev['ref']} | {ev['title'].replace('|', '/')} | `{ev['sha256']}` |"
        )
    lines += ["", f"Report digest: `{report['sha256']}` (exported {report['exported_at']})", ""]
    return "\n".join(lines)
