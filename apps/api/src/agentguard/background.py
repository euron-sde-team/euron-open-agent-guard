"""Jobs and periodic tasks run by the worker.

Jobs (``core.jobs``): approval notifications, running an approved action, threat emails.
Periodic tasks (``core.tasks``, one replica at a time): audit sealing and checkpoints,
overdue approvals, MCP health and rediscovery, behavioural and exfiltration detection,
retention, expiring secrets, SIEM forwarding.
"""

from __future__ import annotations

import contextlib
import logging
import statistics
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import orjson
from sqlalchemy import delete, func, select, text, update

from agentguard.approvals import service as approvals
from agentguard.approvals.models import ApprovalRequest
from agentguard.audit import service as audit_service
from agentguard.audit.models import AuditLog
from agentguard.core import jobs
from agentguard.core.container import Container
from agentguard.core.events import commit
from agentguard.core.mail import MailError, send
from agentguard.core.tasks import periodic
from agentguard.decisions.models import Decision, DecisionToken
from agentguard.identity.models import Agent, RequestNonce
from agentguard.integrations.models import Integration
from agentguard.mcp import catalog
from agentguard.mcp.models import McpServer
from agentguard.network.models import EgressEvent
from agentguard.org import service as org_service
from agentguard.org.models import Org
from agentguard.protection.detectors import redact_value
from agentguard.secrets.models import Secret
from agentguard.threats import service as threats
from agentguard.threats.models import SEVERITIES, AgentBaseline, ThreatEvent
from agentguard.users.models import User

log = logging.getLogger("agentguard.background")
RESULT_MAX_BYTES = 50_000


def _now() -> datetime:
    return datetime.now(UTC)


@jobs.handles(approvals.NOTIFY)
async def notify_reviewers(ctx: jobs.JobContext) -> None:
    container = ctx.container
    async with container.db.sessionmaker() as session:
        request = await session.get(ApprovalRequest, uuid.UUID(ctx.payload["approval_id"]))
        if request is None or request.status != "pending":
            return
        bundle = await org_service.load(session, request.org_id)
        if not bundle.notifications.approval_emails:
            return
        agent = await session.get(Agent, request.agent_id)
        reviewers = await approvals.reviewers_for(session, request)
    link = f"{container.settings.public_url}/approvals/{request.id}"
    for user in reviewers:
        with contextlib.suppress(MailError):
            await send(
                container.settings,
                user.email,
                f"Approval needed: {agent.slug if agent else 'an agent'} wants to {request.action} {request.tool}",
                (
                    f"{agent.name if agent else 'An agent'} asked to run {request.tool} ({request.action})"
                    f"{' on ' + request.resource if request.resource else ''}.\n\n"
                    f"Why it needs a person: {request.reason}\nRisk: {request.risk_level}\n"
                    f"Expires: {request.expires_at:%Y-%m-%d %H:%M} UTC\n\n"
                    f"Review the exact parameters and decide: {link}\n"
                ),
                headers={"X-AgentGuard-Approval": str(request.id)},
            )


@jobs.handles(approvals.EXECUTE)
async def execute_approved(ctx: jobs.JobContext) -> None:
    """Run an approved action through the whole pipeline again (policies re-checked now)."""
    from agentguard.decisions import service as decisions
    from agentguard.decisions.schemas import AuthorizeRequest
    from agentguard.identity.service import AgentPrincipal

    container = ctx.container
    approval_id = uuid.UUID(ctx.payload["approval_id"])
    async with container.db.sessionmaker() as session:
        request = await session.get(ApprovalRequest, approval_id)
        if request is None or request.status != "approved":
            return
        agent = await session.get(Agent, request.agent_id)
        if agent is None:
            return
        params = await approvals.params_of(container, request)
        from agentguard.decisions.models import Run

        run = await session.get(Run, request.run_id) if request.run_id else None
        body = AuthorizeRequest(
            tool=request.tool,
            action=request.action,
            resource=request.resource or None,
            parameters=params,
            run_id=run.run_key if run else None,
            on_behalf_of=request.on_behalf_of,
            approval_id=request.id,
        )
        out = await decisions.execute(
            container,
            session,
            AgentPrincipal(agent, uuid.UUID(int=0), "approval"),
            body,
            ip=None,
            source="execute",
        )
    async with ctx.fenced() as session:
        row = await session.get(ApprovalRequest, approval_id)
        if row is None:
            return
        result: dict[str, Any] = {
            "decision": out.would_be,
            "reason": out.reason,
            "executed": out.executed,
            "meta": out.result_meta,
        }
        if out.executed:
            encoded = orjson.dumps(redact_value(out.result), default=str)
            result["result"] = (
                orjson.loads(encoded)
                if len(encoded) <= RESULT_MAX_BYTES
                else {"truncated": True, "bytes": len(encoded)}
            )
        row.result = result
        if not out.executed and row.status == "approved":
            row.status = "failed"
            approvals.history(
                session, row, "failed", "agentguard", reason=out.reason, decision=out.would_be
            )
        elif row.status == "approved":
            # Policy relaxed meanwhile and the action ran on a plain allow: the approval is
            # used up all the same, so it can never be redeemed again.
            row.status, row.executed_at = "executed", datetime.now(UTC)
            approvals.history(session, row, "executed", "agentguard", decision=out.would_be)


@jobs.handles("notify.threat")
async def notify_threat(ctx: jobs.JobContext) -> None:
    container = ctx.container
    async with container.db.sessionmaker() as session:
        event = await session.get(ThreatEvent, uuid.UUID(ctx.payload["threat_id"]))
        if event is None:
            return
        bundle = await org_service.load(session, event.org_id)
        minimum = bundle.notifications.threat_email_min_severity
        if minimum == "off" or SEVERITIES.index(event.severity) < SEVERITIES.index(minimum):
            return
        recipients = [
            u.email
            for u in (
                await session.scalars(
                    select(User).where(
                        User.org_id == event.org_id,
                        User.disabled.is_(False),
                        User.role.in_(("security_officer", "org_admin")),
                    )
                )
            ).all()
        ] + list(bundle.notifications.extra_recipients)
    for email in sorted(set(recipients)):
        with contextlib.suppress(MailError):
            await send(
                container.settings,
                email,
                f"[{event.severity.upper()}] {event.summary}"[:200],
                (
                    f"AgentGuard detected {event.kind.replace('_', ' ')} ({event.severity}).\n\n{event.summary}\n\n"
                    f"Automatic response: {', '.join(map(str, event.responses)) or 'none'}\n\n"
                    f"Investigate: {container.settings.public_url}/threats/{event.id}\n"
                ),
            )


@periodic("audit.seal", every_s=2.0)
async def seal_audit(container: Container) -> int:
    total = 0
    async with container.db.sessionmaker() as session:
        orgs = await audit_service.orgs_with_unsealed(session)
    for org_id in orgs:
        async with container.db.sessionmaker() as session:
            total += await audit_service.seal(session, org_id)
    return total


@periodic("audit.checkpoint", every_s=300.0)
async def checkpoint_audit(container: Container) -> int:
    count = 0
    async with container.db.sessionmaker() as session:
        org_ids = list((await session.scalars(select(Org.id))).all())
    for org_id in org_ids:
        async with container.db.sessionmaker() as session:
            if (
                await audit_service.checkpoint(
                    session, org_id, container.keys, container.audit_storage
                )
                is not None
            ):
                count += 1
    return count


@periodic("approvals.expire", every_s=60.0)
async def expire_approvals(container: Container) -> int:
    return await approvals.expire_overdue(container)


@periodic("mcp.health", every_s=60.0)
async def mcp_health(container: Container) -> int:
    async with container.db.sessionmaker() as session:
        servers = list(
            (await session.scalars(select(McpServer).where(McpServer.enabled.is_(True)))).all()
        )
        for server in servers:
            await catalog.check_health(container, session, server)
        await session.commit()
    return len(servers)


@periodic("mcp.discover", every_s=600.0)
async def mcp_discover(container: Container) -> int:
    """Rediscover every server: a changed tool definition is held for review."""
    count = 0
    async with container.db.sessionmaker() as session:
        ids = list(
            (await session.scalars(select(McpServer.id).where(McpServer.enabled.is_(True)))).all()
        )
    for server_id in ids:
        async with container.db.sessionmaker() as session:
            server = await session.get(McpServer, server_id)
            if server is None:
                continue
            try:
                await catalog.discover(container, session, server)
                await commit(container, session)
                count += 1
            except Exception as exc:  # one broken server must not stop the others
                await session.rollback()
                log.warning(
                    "mcp discovery failed",
                    extra={"server": str(server_id), "error": type(exc).__name__},
                )
    return count


def _robust_z(value: float, history: list[float]) -> float:
    if len(history) < 6:
        return 0.0
    median = statistics.median(history)
    mad = statistics.median(abs(x - median) for x in history) or 1.0
    return (value - median) / (1.4826 * mad)


@periodic("threats.behaviour", every_s=300.0)
async def behaviour(container: Container) -> int:
    """Per agent: hourly call volume against its own last 7 days, and tools it never used.

    A robust z-score (median and MAD) of the last hour's volume above the organisation's
    threshold, or a burst of first-time tools from an agent with an established baseline,
    raises a behavioural anomaly.
    """
    now = _now()
    hour_ago = now - timedelta(hours=1)
    week_ago = now - timedelta(days=7)
    raised = 0
    async with container.db.sessionmaker() as session:
        agents = list((await session.scalars(select(Agent).where(Agent.status == "active"))).all())
        for agent in agents:
            bucket = func.date_trunc("hour", Decision.at)
            hourly = [
                float(c)
                for _, c in (
                    await session.execute(
                        select(bucket, func.count())
                        .where(
                            Decision.agent_id == agent.id,
                            Decision.at >= week_ago,
                            Decision.at < hour_ago,
                        )
                        .group_by(bucket)
                    )
                ).all()
            ]
            known = set(
                (
                    await session.scalars(
                        select(Decision.tool)
                        .where(
                            Decision.agent_id == agent.id,
                            Decision.at >= week_ago,
                            Decision.at < hour_ago,
                        )
                        .distinct()
                    )
                ).all()
            )
            recent = list(
                (
                    await session.execute(
                        select(Decision.tool, func.count())
                        .where(Decision.agent_id == agent.id, Decision.at >= hour_ago)
                        .group_by(Decision.tool)
                    )
                ).all()
            )
            volume = float(sum(c for _, c in recent))
            new_tools = sorted(t for t, _ in recent if t not in known)
            baseline = await session.scalar(
                select(AgentBaseline).where(AgentBaseline.agent_id == agent.id)
            )
            stats = {
                "hours": len(hourly),
                "median": statistics.median(hourly) if hourly else 0,
                "tools": len(known),
            }
            if baseline is None:
                session.add(AgentBaseline(org_id=agent.org_id, agent_id=agent.id, stats=stats))
            else:
                baseline.stats, baseline.computed_at = stats, now
            bundle = await org_service.load(session, agent.org_id)
            z = _robust_z(volume, hourly)
            if z >= bundle.detection.anomaly_z and volume >= 20:
                await threats.record(
                    session,
                    agent.org_id,
                    kind="behavioural_anomaly",
                    severity="medium",
                    rule="volume_z",
                    summary=f"{agent.slug} made {int(volume)} calls in the last hour (usual {stats['median']:.0f}, z {z:.1f})",
                    agent_id=agent.id,
                    detector="behavioural",
                    details={"z": round(z, 2), "volume": volume, **stats},
                    dedupe="volume",
                )
                raised += 1
            if len(hourly) >= 24 and len(known) >= 2 and len(new_tools) >= 3:
                await threats.record(
                    session,
                    agent.org_id,
                    kind="behavioural_anomaly",
                    severity="medium",
                    rule="new_tools",
                    summary=f"{agent.slug} used {len(new_tools)} tools it never used before",
                    agent_id=agent.id,
                    detector="behavioural",
                    details={"new_tools": new_tools[:20]},
                    dedupe="new_tools",
                )
                raised += 1
        await commit(container, session)
    return raised


@periodic("threats.exfiltration", every_s=60.0)
async def exfiltration(container: Container) -> int:
    """Large uploads to destinations an agent never used before."""
    now = _now()
    window = now - timedelta(minutes=5)
    raised = 0
    async with container.db.sessionmaker() as session:
        rows = (
            await session.execute(
                select(
                    EgressEvent.org_id,
                    EgressEvent.agent_id,
                    EgressEvent.host,
                    func.sum(EgressEvent.bytes_up),
                )
                .where(
                    EgressEvent.at >= window,
                    EgressEvent.decision == "allow",
                    EgressEvent.agent_id.is_not(None),
                )
                .group_by(EgressEvent.org_id, EgressEvent.agent_id, EgressEvent.host)
                .having(func.sum(EgressEvent.bytes_up) >= 1_000_000)
            )
        ).all()
        for org_id, agent_id, host, sent in rows:
            seen_before = await session.scalar(
                select(func.count())
                .select_from(EgressEvent)
                .where(
                    EgressEvent.agent_id == agent_id,
                    EgressEvent.host == host,
                    EgressEvent.at < window,
                    EgressEvent.at >= now - timedelta(days=30),
                )
            )
            if seen_before:
                continue
            await threats.record(
                session,
                org_id,
                kind="data_exfiltration",
                severity="high",
                rule="large_upload_new_destination",
                summary=f"{int(sent) // 1_000_000} MB sent to {host}, a destination this agent never used",
                agent_id=agent_id,
                details={"host": host, "bytes": int(sent)},
                dedupe=host,
            )
            raised += 1
        await commit(container, session)
    return raised


@periodic("retention", every_s=3600.0)
async def retention(container: Container) -> int:
    now = _now()
    changed = 0
    async with container.db.sessionmaker() as session:
        org_ids = list((await session.scalars(select(Org.id))).all())
        await session.execute(
            delete(DecisionToken).where(DecisionToken.expires_at < now - timedelta(days=1))
        )
        await session.execute(
            delete(RequestNonce).where(RequestNonce.seen_at < now - timedelta(hours=1))
        )
        await session.commit()
    for org_id in org_ids:
        async with container.db.sessionmaker() as session:
            bundle = await org_service.load(session, org_id, fresh=True)
            r = bundle.retention
            result = await session.execute(
                update(Decision)
                .where(
                    Decision.org_id == org_id,
                    Decision.at < now - timedelta(days=r.decision_payload_days),
                    Decision.params != text("'{}'::jsonb"),
                )
                .values(params={}, context={})
            )
            changed += int(result.rowcount or 0)  # type: ignore[attr-defined]
            result = await session.execute(
                delete(EgressEvent).where(
                    EgressEvent.org_id == org_id,
                    EgressEvent.at < now - timedelta(days=r.egress_days),
                )
            )
            changed += int(result.rowcount or 0)  # type: ignore[attr-defined]
            await session.commit()
            changed += await audit_service.prune_details(
                session, org_id, now - timedelta(days=r.audit_details_days)
            )
    return changed


@periodic("secrets.expiring", every_s=3600.0)
async def expiring_secrets(container: Container) -> int:
    from agentguard.integrations.service import dispatch

    now = _now()
    count = 0
    async with container.db.sessionmaker() as session:
        rows = (
            await session.scalars(
                select(Secret).where(
                    Secret.revoked_at.is_(None),
                    Secret.expires_at.is_not(None),
                    Secret.expires_at > now,
                    Secret.expires_at <= now + timedelta(days=7),
                )
            )
        ).all()
        for secret in rows:
            day = now.date().isoformat()
            key = f"secret-expiring:{secret.id}:{day}"
            ok, _ = await container.kv.window_add(key, 1, 1, 86_400)
            if not ok:
                continue
            await dispatch(
                session,
                secret.org_id,
                "secret.expiring",
                {
                    "secret": secret.name,
                    "expires_at": secret.expires_at.isoformat() if secret.expires_at else None,
                },
            )
            count += 1
        await session.commit()
    return count


@periodic("siem.forward", every_s=30.0)
async def siem_forward(container: Container) -> int:
    """Send newly sealed audit records to each organisation's SIEM endpoint, in order."""
    from agentguard.core.net import resolves_safely
    from agentguard.integrations.tokenshield import SECRET_CONTEXT

    sent = 0
    async with container.db.sessionmaker() as session:
        rows = list(
            (
                await session.scalars(
                    select(Integration).where(
                        Integration.kind == "siem", Integration.enabled.is_(True)
                    )
                )
            ).all()
        )
        for row in rows:
            url = str(row.config.get("url") or "")
            if not url or not await resolves_safely(
                url, allow_private=container.settings.allow_private_urls
            ):
                continue
            last = int(row.config.get("last_seq", 0))
            records = (
                await session.scalars(
                    select(AuditLog)
                    .where(
                        AuditLog.org_id == row.org_id,
                        AuditLog.seq > last,
                        AuditLog.hash.is_not(None),
                    )
                    .order_by(AuditLog.seq)
                    .limit(500)
                )
            ).all()
            if not records:
                continue
            headers = {"content-type": "application/x-ndjson"}
            if row.secret_sealed is not None:
                token = await container.sealer.open(
                    row.secret_sealed, SECRET_CONTEXT.format(id=row.id)
                )
                headers["authorization"] = f"Bearer {token}"
            body = b"".join(
                orjson.dumps(
                    {
                        "seq": r.seq,
                        "at": r.at.isoformat(),
                        "actor": r.actor_name,
                        "actor_type": r.actor_type,
                        "action": r.action,
                        "target_type": r.target_type,
                        "target_id": r.target_id,
                        "details": r.details,
                        "hash": r.hash,
                        "org_id": str(r.org_id),
                    }
                )
                + b"\n"
                for r in records
            )
            try:
                resp = await container.http.post(url, content=body, headers=headers, timeout=10.0)
                ok = resp.status_code < 300
                detail = f"HTTP {resp.status_code}"
            except Exception as exc:
                ok, detail = False, type(exc).__name__
            if ok:
                row.config = {**row.config, "last_seq": records[-1].seq}
                row.last_ok_at, row.last_error = _now(), None
                sent += len(records)
            else:
                row.last_error = detail
        await session.commit()
    return sent
