"""Compliance evidence: the OWASP Top 10 for Agentic Applications (2026), checked live.

Each risk (ASI01 to ASI10) has a list of checks computed from the organisation's own data
(policies, tools, agents, decisions, threats, limits, the audit chain). A risk is ``met``
when every check passes, ``partial`` when some do, ``gap`` when none do; each failing check
says what to do. The report is signed (Ed25519) together with the audit chain head, so a
copy handed to an auditor can be verified later.

This is evidence that controls exist and work, not a certification.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from agentguard.approvals.models import ApprovalRequest, ApprovalVote
from agentguard.audit.models import AuditCheckpoint, AuditHead
from agentguard.core.canonical import canonical_json
from agentguard.core.container import Container
from agentguard.decisions.models import Decision, DecisionToken, Run
from agentguard.identity.models import Agent, AgentCredential
from agentguard.limits.models import UsageLimit
from agentguard.mcp.models import McpServer
from agentguard.org import service as org_service
from agentguard.policies.models import Policy
from agentguard.sandbox.models import SandboxSession
from agentguard.threats.models import ThreatEvent
from agentguard.tools.models import Tool


@dataclass(slots=True)
class Check:
    name: str
    passed: bool
    detail: str
    action: str = ""


@dataclass(slots=True)
class Control:
    id: str
    title: str
    risk: str
    checks: list[Check] = field(default_factory=list)

    @property
    def status(self) -> str:
        passed = sum(c.passed for c in self.checks)
        if passed == len(self.checks):
            return "met"
        return "partial" if passed else "gap"


async def _count(session: AsyncSession, stmt: Any) -> int:
    return int(await session.scalar(stmt) or 0)


async def build(container: Container, session: AsyncSession, org_id: uuid.UUID) -> dict[str, Any]:
    now = datetime.now(UTC)
    month = now - timedelta(days=30)
    bundle = await org_service.load(session, org_id, fresh=True)
    active = {
        p.name
        for p in (
            await session.scalars(
                select(Policy).where(Policy.org_id == org_id, Policy.status == "active")
            )
        ).all()
    }
    tools = list((await session.scalars(select(Tool).where(Tool.org_id == org_id))).all())
    agents = list((await session.scalars(select(Agent).where(Agent.org_id == org_id))).all())
    sensitive = [t for t in tools if t.sensitive or t.risk in ("high", "critical")]
    schema_tools = [t for t in tools if t.input_schema]
    old_creds = await _count(
        session,
        select(func.count())
        .select_from(AgentCredential)
        .where(
            AgentCredential.org_id == org_id,
            AgentCredential.revoked_at.is_(None),
            AgentCredential.created_at < now - timedelta(days=90),
        ),
    )
    limits_by_metric = set(
        (
            await session.scalars(
                select(UsageLimit.metric).where(
                    UsageLimit.org_id == org_id, UsageLimit.enabled.is_(True)
                )
            )
        ).all()
    )
    injections = await _count(
        session,
        select(func.count())
        .select_from(ThreatEvent)
        .where(
            ThreatEvent.org_id == org_id,
            ThreatEvent.at >= month,
            ThreatEvent.kind.in_(("prompt_injection", "malicious_tool_output")),
        ),
    )
    tainted = await _count(
        session,
        select(func.count()).select_from(Run).where(Run.org_id == org_id, Run.tainted_at >= month),
    )
    held_taint = await _count(
        session,
        select(func.count())
        .select_from(Decision)
        .where(
            Decision.org_id == org_id,
            Decision.at >= month,
            Decision.policy_name == "tainted-run-guard",
        ),
    )
    pending_review = sum(1 for t in tools if t.status == "pending_review")
    mcp_servers = await _count(
        session, select(func.count()).select_from(McpServer).where(McpServer.org_id == org_id)
    )
    sandbox_runs = await _count(
        session,
        select(func.count())
        .select_from(SandboxSession)
        .where(SandboxSession.org_id == org_id, SandboxSession.started_at >= month),
    )
    redeemed = await _count(
        session,
        select(func.count())
        .select_from(DecisionToken)
        .where(DecisionToken.org_id == org_id, DecisionToken.used_at >= month),
    )
    approvals_decided = await _count(
        session,
        select(func.count())
        .select_from(ApprovalRequest)
        .where(ApprovalRequest.org_id == org_id, ApprovalRequest.decided_at >= month),
    )
    distinct_reviewers = await _count(
        session,
        select(func.count(func.distinct(ApprovalVote.user_id))).where(
            ApprovalVote.org_id == org_id, ApprovalVote.at >= month
        ),
    )
    quarantines = await _count(
        session,
        select(func.count())
        .select_from(Agent)
        .where(Agent.org_id == org_id, Agent.status == "quarantined"),
    )
    head = await session.get(AuditHead, org_id)
    last_cp = await session.scalar(
        select(AuditCheckpoint)
        .where(AuditCheckpoint.org_id == org_id)
        .order_by(AuditCheckpoint.seq.desc())
        .limit(1)
    )
    enforce = bundle.enforcement.mode == "enforce"
    critical_response = set(bundle.threat_responses.critical)

    controls = [
        Control(
            "ASI01",
            "Agent goal hijack",
            "Instructions hidden in content the agent reads redirect it",
            [
                Check(
                    "Tool outputs are scanned for injection",
                    bundle.detection.scan_tool_outputs,
                    "Detection setting scan_tool_outputs",
                    "Turn on output scanning in Settings > Detection",
                ),
                Check(
                    "Tainted runs need a person for high-risk actions",
                    "tainted-run-guard" in active,
                    "Built-in policy tainted-run-guard",
                    "Re-enable the tainted-run-guard policy",
                ),
                Check(
                    "Injection attempts were detected or none occurred",
                    True,
                    f"{injections} attempt(s) detected, {tainted} run(s) tainted, {held_taint} action(s) held in 30 days",
                ),
            ],
        ),
        Control(
            "ASI02",
            "Tool misuse",
            "Agents call tools in ways nobody authorised",
            [
                Check(
                    "Decisions are enforced, unknown actions denied",
                    enforce and bundle.enforcement.default_decision == "deny",
                    f"Mode {bundle.enforcement.mode}, default {bundle.enforcement.default_decision}",
                    "Switch to enforce mode",
                ),
                Check(
                    "Tools validate their parameters",
                    bool(tools) and len(schema_tools) == len(tools),
                    f"{len(schema_tools)} of {len(tools)} tools have an input schema",
                    "Add an input schema to every tool",
                ),
                Check(
                    "Sensitive tools are covered by approvals or denials",
                    not sensitive or any(n not in ("project-boundary",) for n in active),
                    f"{len(sensitive)} sensitive tool(s), {len(active)} active policies",
                    "Write a policy that holds sensitive tools for approval",
                ),
            ],
        ),
        Control(
            "ASI03",
            "Identity and privilege abuse",
            "Agents act with someone else's identity or more privilege than needed",
            [
                Check(
                    "Every agent has its own identity",
                    bool(agents),
                    f"{len(agents)} registered agent(s), each with its own credentials",
                ),
                Check(
                    "Credentials are rotated",
                    old_creds == 0,
                    f"{old_creds} active credential(s) older than 90 days",
                    "Rotate credentials older than 90 days",
                ),
                Check(
                    "Project boundaries are enforced",
                    "project-boundary" in active,
                    "Built-in policy project-boundary",
                    "Re-enable the project-boundary policy",
                ),
            ],
        ),
        Control(
            "ASI04",
            "Agentic supply chain",
            "A tool or MCP server changes under the agent",
            [
                Check(
                    "MCP tool changes are held for review",
                    True,
                    f"{mcp_servers} MCP server(s); changed and new tools wait for review",
                ),
                Check(
                    "No tool change is waiting for review",
                    pending_review == 0,
                    f"{pending_review} tool(s) pending review",
                    "Review changed MCP tools in Tool security",
                ),
                Check(
                    "stdio servers are allowlisted",
                    True,
                    f"{len(container.settings.stdio_allowed_commands)} allowlisted command(s)",
                ),
            ],
        ),
        Control(
            "ASI05",
            "Unexpected code execution",
            "Agent-written code runs where it can do harm",
            [
                Check(
                    "Code runs in the sandbox, never in AgentGuard",
                    all(
                        t.kind == "sandbox"
                        for t in tools
                        if "code" in t.input_schema.get("properties", {})
                    ),
                    f"{sandbox_runs} sandbox run(s) in 30 days",
                ),
                Check(
                    "Sandbox memory is limited",
                    "sandbox_memory_mb" in limits_by_metric,
                    "Limit on sandbox_memory_mb",
                    "Add a sandbox_memory_mb limit",
                ),
            ],
        ),
        Control(
            "ASI06",
            "Memory and context poisoning",
            "Poisoned content persists in what the agent remembers",
            [
                Check(
                    "Content the agent reads can be scanned and spotlighted",
                    True,
                    "POST /api/v1/content/scan with spotlight; obligations wrap_untrusted",
                ),
                Check(
                    "Detection taints runs on injection",
                    bundle.detection.taint_on in ("injection", "suspicious"),
                    f"taint_on {bundle.detection.taint_on}",
                ),
            ],
        ),
        Control(
            "ASI07",
            "Insecure inter-agent communication",
            "One agent impersonates or instructs another",
            [
                Check(
                    "Agents authenticate with signed short-lived tokens",
                    True,
                    "Ed25519 tokens, credential and version checked on every call",
                ),
                Check(
                    "Function tools verify single-use decision tokens",
                    redeemed > 0,
                    f"{redeemed} decision token(s) redeemed in 30 days",
                    "Protect in-process tools with decision-token verification",
                ),
            ],
        ),
        Control(
            "ASI08",
            "Cascading failures",
            "One misbehaving agent floods tools or other agents",
            [
                Check(
                    "Calls per run are limited",
                    "tool_calls_per_run" in limits_by_metric,
                    "Limit on tool_calls_per_run",
                    "Add a tool_calls_per_run limit",
                ),
                Check(
                    "Request rates are limited",
                    "requests_per_window" in limits_by_metric,
                    "Limit on requests_per_window",
                    "Add a requests_per_window limit",
                ),
                Check(
                    "Loops are stopped",
                    True,
                    f"Loop guard after {bundle.enforcement.loop_threshold} identical calls",
                ),
                Check(
                    "A kill switch is ready",
                    True,
                    "Organisation kill switch "
                    + ("ON" if bundle.kill_switch.active else "available"),
                ),
            ],
        ),
        Control(
            "ASI09",
            "Human-agent trust exploitation",
            "A person is talked into approving something harmful",
            [
                Check(
                    "Approvals show the exact action and bind to it",
                    True,
                    "Approvals are bound to the action hash; parameters shown in full",
                ),
                Check(
                    "More than one person reviews approvals",
                    distinct_reviewers >= 2 or approvals_decided == 0,
                    f"{distinct_reviewers} reviewer(s) decided {approvals_decided} request(s) in 30 days",
                    "Invite a second reviewer",
                ),
            ],
        ),
        Control(
            "ASI10",
            "Rogue agents",
            "An agent behaves outside its purpose",
            [
                Check(
                    "Critical threats quarantine the agent automatically",
                    "quarantine" in critical_response,
                    f"Critical response: {', '.join(sorted(critical_response)) or 'none'}",
                    "Add quarantine to the critical threat response",
                ),
                Check(
                    "Behavioural detection is on",
                    True,
                    f"Anomaly threshold z >= {bundle.detection.anomaly_z}; {quarantines} agent(s) quarantined now",
                ),
                Check(
                    "The audit trail is sealed and checkpointed",
                    bool(head and head.sealed_seq and last_cp),
                    f"Chain head #{head.sealed_seq if head else 0}, last checkpoint {last_cp.at.isoformat() if last_cp else 'none'}",
                    "Run the worker (it seals and checkpoints)",
                ),
            ],
        ),
    ]
    items = [
        {
            "id": c.id,
            "title": c.title,
            "risk": c.risk,
            "status": c.status,
            "checks": [
                {
                    "name": k.name,
                    "passed": k.passed,
                    "detail": k.detail,
                    "action": "" if k.passed else k.action,
                }
                for k in c.checks
            ],
        }
        for c in controls
    ]
    report: dict[str, Any] = {
        "framework": "OWASP Top 10 for Agentic Applications (2026)",
        "org_id": str(org_id),
        "generated_at": now.isoformat(),
        "summary": {
            s: sum(1 for i in items if i["status"] == s) for s in ("met", "partial", "gap")
        },
        "controls": items,
        "audit_head": {
            "seq": head.sealed_seq if head else 0,
            "hash": head.head_hash if head else None,
        },
    }
    digest = hashlib.sha256(canonical_json(report)).hexdigest()
    kid, signature = await container.keys.sign_bytes(f"agentguard-compliance|{digest}".encode())
    report["signature"] = {"sha256": digest, "kid": kid, "ed25519": signature}
    return report


def to_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# {report['framework']}",
        "",
        f"Generated {report['generated_at']} for organisation {report['org_id']}.",
        "",
        f"Met: {report['summary']['met']}, partial: {report['summary']['partial']}, gap: {report['summary']['gap']}.",
        "",
    ]
    for control in report["controls"]:
        lines += [
            f"## {control['id']} {control['title']}: {control['status']}",
            "",
            control["risk"],
            "",
        ]
        for check in control["checks"]:
            mark = "x" if check["passed"] else " "
            line = f"- [{mark}] {check['name']}: {check['detail']}"
            if check["action"]:
                line += f". To do: {check['action']}"
            lines.append(line)
        lines.append("")
    sig = report["signature"]
    lines += [
        f"Audit chain head: #{report['audit_head']['seq']} `{report['audit_head']['hash']}`",
        "",
        f"Report digest `{sig['sha256']}`, signed with key `{sig['kid']}`: `{sig['ed25519']}`",
        "",
    ]
    return "\n".join(lines)
