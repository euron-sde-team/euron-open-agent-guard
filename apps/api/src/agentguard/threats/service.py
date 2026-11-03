"""Recording threats and responding to them.

:func:`record` is called by every detector (inline in the decision pipeline, by the worker's
analysers, by the MCP gateway and the egress proxy). Repeats of the same threat for the same
agent fold into one open event (``occurrences`` counts them) instead of flooding the list.

Responses are configured per organisation and severity (``org_settings.threat_responses``),
for example: ``critical`` quarantines the agent, revokes its credentials, opens an incident
and notifies; ``high`` opens an incident and notifies. They run in the same transaction as
the detection, so a quarantine is in force before the response to the request that
triggered it is sent.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from agentguard.audit.service import system_actor
from agentguard.core import events
from agentguard.threats.models import SEVERITIES, ThreatEvent

log = logging.getLogger("agentguard.threats")

DEFAULT_RESPONSES: dict[str, list[str]] = {
    "critical": ["quarantine", "revoke_credentials", "incident", "notify"],
    "high": ["incident", "notify"],
    "medium": ["notify"],
    "low": [],
}


def _now() -> datetime:
    return datetime.now(UTC)


async def record(
    session: AsyncSession,
    org_id: uuid.UUID,
    *,
    kind: str,
    severity: str,
    rule: str,
    summary: str,
    agent_id: uuid.UUID | None = None,
    run_id: uuid.UUID | None = None,
    decision_id: uuid.UUID | None = None,
    details: dict[str, Any] | None = None,
    detector: str = "rule",
    dedupe: str | None = None,
    respond: bool = True,
) -> ThreatEvent:
    assert severity in SEVERITIES
    dedupe_key = f"{agent_id}:{kind}:{dedupe}" if dedupe is not None else None
    if dedupe_key is not None:
        existing = await session.scalar(
            select(ThreatEvent)
            .where(
                ThreatEvent.org_id == org_id,
                ThreatEvent.dedupe_key == dedupe_key,
                ThreatEvent.status == "open",
            )
            .with_for_update()
        )
        if existing is not None:
            existing.occurrences += 1
            existing.last_seen_at = _now()
            if SEVERITIES.index(severity) > SEVERITIES.index(existing.severity):
                existing.severity = severity
            return existing
    event = ThreatEvent(
        org_id=org_id,
        agent_id=agent_id,
        run_id=run_id,
        decision_id=decision_id,
        kind=kind,
        severity=severity,
        detector=detector,
        rule=rule,
        summary=summary[:500],
        details=details or {},
        dedupe_key=dedupe_key,
    )
    session.add(event)
    await session.flush()
    log.warning(
        "threat detected",
        extra={
            "kind": kind,
            "severity": severity,
            "rule": rule,
            "agent_id": str(agent_id),
            "org_id": str(org_id),
        },
    )
    events.emit(
        session, f"org:{org_id}", {"type": "threat", "id": str(event.id), "severity": severity}
    )
    from agentguard.integrations.service import dispatch

    await dispatch(
        session,
        org_id,
        "threat.detected",
        {
            "id": str(event.id),
            "kind": kind,
            "severity": severity,
            "summary": event.summary,
            "agent_id": str(agent_id) if agent_id else None,
        },
    )
    if respond:
        await respond_to(session, event)
    return event


async def respond_to(session: AsyncSession, event: ThreatEvent) -> list[str]:
    """Run the organisation's automatic response for this event's severity."""
    from agentguard.org.models import OrgSettings

    settings = await session.get(OrgSettings, event.org_id)
    configured = (settings.threat_responses if settings else {}) or {}
    actions = list(configured.get(event.severity, DEFAULT_RESPONSES.get(event.severity, [])))
    done: list[str] = []
    actor = system_actor(event.org_id, "threat-response")
    if event.agent_id is not None and ("quarantine" in actions or "revoke_credentials" in actions):
        from agentguard.identity import service as identity
        from agentguard.identity.models import Agent

        agent = await session.get(Agent, event.agent_id)
        if agent is not None and agent.status != "revoked":
            if "quarantine" in actions and agent.status in ("active", "suspended"):
                await identity.set_status(
                    session,
                    actor,
                    agent,
                    "quarantined",
                    f"Automatic response to {event.kind}: {event.summary}",
                )
                done.append("quarantined")
            if "revoke_credentials" in actions:
                # Whatever the agent's status: a critical threat means its credentials may
                # be in the wrong hands.
                await identity.revoke_all_credentials(session, actor, agent)
                done.append("credentials_revoked")
    if "incident" in actions and event.incident_id is None:
        from agentguard.incidents import service as incidents

        incident = await incidents.open_from_threat(session, event)
        event.incident_id = incident.id
        done.append(f"incident:INC-{incident.number}")
    if "notify" in actions:
        from agentguard.core import jobs

        await jobs.enqueue(
            session,
            "notify.threat",
            {"threat_id": str(event.id)},
            org_id=event.org_id,
            max_attempts=5,
        )
        done.append("notified")
    event.responses = [*event.responses, *done]
    return done


async def open_count(session: AsyncSession, agent_id: uuid.UUID) -> int:
    from sqlalchemy import func

    return int(
        await session.scalar(
            select(func.count())
            .select_from(ThreatEvent)
            .where(ThreatEvent.agent_id == agent_id, ThreatEvent.status == "open")
        )
        or 0
    )


async def set_status(
    session: AsyncSession, org_id: uuid.UUID, threat_id: uuid.UUID, status: str
) -> ThreatEvent | None:
    event = await session.get(ThreatEvent, threat_id)
    if event is None or event.org_id != org_id:
        return None
    await session.execute(
        update(ThreatEvent).where(ThreatEvent.id == threat_id).values(status=status)
    )
    event.status = status
    return event
