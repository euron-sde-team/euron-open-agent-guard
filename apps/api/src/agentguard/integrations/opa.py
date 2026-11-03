"""Optional Open Policy Agent decision point.

An organisation that already writes Rego can add a package; AgentGuard sends OPA the same
evaluation input its own engine sees (``POST /v1/data/<package>/decision``) and combines
the answer **deny-overrides** with its own decision: OPA can make a decision stricter,
never more permissive. The API of AgentGuard does not change when OPA is used.

The expected result is either ``{"decision": "deny", "reason": "..."}`` (any AgentGuard
decision) or a boolean ``allow`` (false means deny). When OPA cannot be reached, sensitive
tools are denied (``opa_unavailable``) and others continue on AgentGuard's own decision.

Rego uploaded in the dashboard is pushed to OPA as ``agentguard/<org id>`` on save.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agentguard.core.container import Container
from agentguard.integrations.models import Integration

DECISIONS = ("allow", "deny", "require_approval", "restrict", "quarantine")


@dataclass(frozen=True, slots=True)
class OpaResult:
    decision: str | None
    reason: str
    error: str | None = None


async def config_for(session: AsyncSession, org_id: uuid.UUID) -> Integration | None:
    row = await session.scalar(
        select(Integration).where(
            Integration.org_id == org_id, Integration.kind == "opa", Integration.enabled.is_(True)
        )
    )
    return row


def _base(container: Container, row: Integration) -> str:
    return str(row.config.get("url") or container.settings.opa_url).rstrip("/")


def package_path(org_id: uuid.UUID, row: Integration) -> str:
    package = str(row.config.get("package") or f"agentguard.org_{org_id.hex}")
    return package.replace(".", "/")


async def evaluate(
    container: Container, row: Integration, org_id: uuid.UUID, data: dict[str, Any]
) -> OpaResult:
    base = _base(container, row)
    if not base:
        return OpaResult(None, "", "OPA has no URL configured")
    try:
        resp = await container.http.post(
            f"{base}/v1/data/{package_path(org_id, row)}/decision",
            json={"input": data},
            timeout=2.0,
        )
    except Exception as exc:
        return OpaResult(None, "", f"OPA unreachable: {type(exc).__name__}")
    if resp.status_code != 200:
        return OpaResult(None, "", f"OPA returned {resp.status_code}")
    result = resp.json().get("result")
    if result is None:
        return OpaResult(None, "No OPA rule applied")
    if isinstance(result, bool):
        return OpaResult(
            "allow" if result else "deny", "OPA: allow is false" if not result else "OPA allowed"
        )
    if isinstance(result, dict):
        decision = str(result.get("decision", "")) or (
            "deny" if result.get("allow") is False else None
        )
        if decision is not None and decision not in DECISIONS:
            return OpaResult("deny", f"OPA returned an unknown decision {decision!r}")
        return OpaResult(decision, str(result.get("reason") or f"OPA decided {decision}"))
    return OpaResult("deny", "OPA returned an unexpected result")


async def push_rego(
    container: Container, row: Integration, org_id: uuid.UUID, rego: str
) -> str | None:
    """Upload the organisation's Rego to OPA. Returns an error message, or None."""
    base = _base(container, row)
    try:
        resp = await container.http.put(
            f"{base}/v1/policies/agentguard-{org_id.hex}",
            content=rego.encode(),
            headers={"content-type": "text/plain"},
            timeout=5.0,
        )
    except Exception as exc:
        return f"OPA unreachable: {type(exc).__name__}"
    if resp.status_code >= 300:
        try:
            detail = resp.json().get("message", "")
        except ValueError:
            detail = resp.text[:300]
        return f"OPA refused the policy: {detail}"
    return None
