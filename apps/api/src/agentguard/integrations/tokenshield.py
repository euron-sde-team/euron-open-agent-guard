"""Optional TokenShield budgets.

TokenShield (Euron Open TokenShield) governs model spend; AgentGuard governs actions. When
an organisation connects TokenShield, actions of agents in the mapped projects are denied
(``budget_exhausted``) while one of the watched TokenShield budgets is spent, so an agent
that ran out of model budget also stops acting.

AgentGuard signs in to TokenShield with a viewer account (the password is sealed), reads
``GET /api/v1/budgets`` and caches the result for ``CACHE_S``. When TokenShield cannot be
reached, ``fail_mode`` decides: ``open`` (default) ignores budgets and keeps enforcing
AgentGuard's own limits, ``closed`` denies.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Any

from agentguard.core.container import Container
from agentguard.integrations.models import Integration

CACHE_S = 10.0
SECRET_CONTEXT = "integration:{id}"  # noqa: S105 an encryption context, not a secret


@dataclass(frozen=True, slots=True)
class BudgetState:
    exhausted: bool
    detail: str
    reachable: bool


_cache: dict[uuid.UUID, tuple[float, BudgetState]] = {}
_sessions: dict[uuid.UUID, str] = {}


async def _login(container: Container, row: Integration, base: str) -> str | None:
    if row.secret_sealed is None:
        return None
    password = await container.sealer.open(row.secret_sealed, SECRET_CONTEXT.format(id=row.id))
    resp = await container.http.post(
        f"{base}/api/v1/auth/login",
        json={"email": row.config.get("email", ""), "password": password},
        timeout=3.0,
    )
    if resp.status_code != 200:
        return None
    token = resp.json().get("session_token") or resp.json().get("token")
    return str(token) if token else None


async def state(container: Container, row: Integration, project_slug: str) -> BudgetState | None:
    """The budget state for an agent's project, or None when TokenShield does not apply."""
    projects: list[str] = list(row.config.get("projects") or [])
    if projects and project_slug not in projects:
        return None
    now = time.monotonic()
    hit = _cache.get(row.id)
    if hit is not None and now - hit[0] < CACHE_S:
        return hit[1]
    base = str(row.config.get("url") or container.settings.tokenshield_url).rstrip("/")
    watched = {str(b) for b in row.config.get("budget_ids") or []}
    result: BudgetState
    try:
        token = _sessions.get(row.id) or await _login(container, row, base)
        if token is None:
            raise RuntimeError("sign-in to TokenShield failed")
        resp = await container.http.get(
            f"{base}/api/v1/budgets", headers={"authorization": f"Bearer {token}"}, timeout=3.0
        )
        if resp.status_code == 401:
            _sessions.pop(row.id, None)
            token = await _login(container, row, base)
            if token is None:
                raise RuntimeError("sign-in to TokenShield failed")
            resp = await container.http.get(
                f"{base}/api/v1/budgets", headers={"authorization": f"Bearer {token}"}, timeout=3.0
            )
        resp.raise_for_status()
        _sessions[row.id] = token
        budgets: list[dict[str, Any]] = resp.json()
        spent = [
            b
            for b in budgets
            if b.get("enabled")
            and (not watched or str(b.get("id")) in watched)
            and float(b.get("used_pct") or 0) >= 100.0
        ]
        if spent:
            names = ", ".join(str(b.get("name")) for b in spent[:3])
            result = BudgetState(True, f"TokenShield budget spent: {names}", True)
        else:
            result = BudgetState(False, "Within TokenShield budgets", True)
    except Exception as exc:
        closed = row.config.get("fail_mode") == "closed"
        result = BudgetState(closed, f"TokenShield unreachable ({type(exc).__name__})", False)
    _cache[row.id] = (now, result)
    return result


def forget(integration_id: uuid.UUID) -> None:
    _cache.pop(integration_id, None)
    _sessions.pop(integration_id, None)
