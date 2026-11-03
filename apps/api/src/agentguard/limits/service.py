"""Execution limits, checked in the decision pipeline.

Run-scoped metrics (calls per run, run duration, concurrent runs) come from the ``runs``
table, updated atomically in the decision's transaction. Windowed metrics (requests,
failures, data transfer per window) are atomic counters in the KV store (Redis, or the
process for a single replica): an add happens only if it stays within the limit, so 50
concurrent requests against a limit of 10 let exactly 10 through.

``AgentGuard enforces local limits even when TokenShield is unreachable``: token and spend
budgets are TokenShield's job (``integrations.tokenshield``); everything here works alone.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agentguard.core.container import Container
from agentguard.limits.models import UsageLimit


@dataclass(frozen=True, slots=True)
class Violation:
    limit_id: uuid.UUID
    name: str
    metric: str
    limit: int
    value: int
    on_exceed: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "limit": self.name,
            "metric": self.metric,
            "allowed": self.limit,
            "value": self.value,
            "on_exceed": self.on_exceed,
        }


@dataclass(frozen=True, slots=True)
class Subject:
    org_id: uuid.UUID
    project_id: uuid.UUID
    agent_id: uuid.UUID
    agent_slug: str
    user: str | None


def applies(limit: UsageLimit, s: Subject) -> str | None:
    """The counter key part for this subject, or None when the limit is not for it."""
    if limit.scope_type == "org":
        return str(s.org_id)
    if limit.scope_type == "project":
        if limit.scope_id and limit.scope_id != str(s.project_id):
            return None
        return str(s.project_id)
    if limit.scope_type == "agent":
        if limit.scope_id and limit.scope_id not in (str(s.agent_id), s.agent_slug):
            return None
        return str(s.agent_id)
    if limit.scope_type == "user":
        if s.user is None or (limit.scope_id and limit.scope_id != s.user):
            return None
        return s.user
    return None


async def load(session: AsyncSession, org_id: uuid.UUID) -> list[UsageLimit]:
    return list(
        (
            await session.scalars(
                select(UsageLimit).where(UsageLimit.org_id == org_id, UsageLimit.enabled.is_(True))
            )
        ).all()
    )


async def check(
    container: Container,
    limits: list[UsageLimit],
    subject: Subject,
    *,
    run_calls: int,
    run_started_at: datetime | None,
    concurrent_runs: int,
    sandbox_memory_mb: int | None,
) -> list[Violation]:
    """Count this request and report every limit it breaks.

    ``requests_per_window`` is counted here (only if within the limit). ``failed_attempts``
    and ``data_transfer_bytes`` are checked against what was already counted; they are
    added by :func:`count_failure` and :func:`count_bytes` after the fact.
    """
    out: list[Violation] = []
    now = datetime.now(UTC)
    for limit in limits:
        part = applies(limit, subject)
        if part is None:
            continue
        key = f"limit:{limit.id}:{part}"
        value: int | None = None
        if limit.metric == "tool_calls_per_run":
            value = run_calls
            exceeded = run_calls > limit.limit_value
        elif limit.metric == "run_duration_s":
            value = int((now - run_started_at).total_seconds()) if run_started_at else 0
            exceeded = value > limit.limit_value
        elif limit.metric == "concurrent_runs":
            value = concurrent_runs
            exceeded = concurrent_runs > limit.limit_value
        elif limit.metric == "sandbox_memory_mb":
            value = sandbox_memory_mb or 0
            exceeded = sandbox_memory_mb is not None and sandbox_memory_mb > limit.limit_value
        elif limit.metric == "requests_per_window":
            ok, value = await container.kv.window_add(key, 1, limit.limit_value, limit.window_s)
            exceeded = not ok
            if exceeded:
                value += 1
        elif limit.metric in ("failed_attempts", "data_transfer_bytes"):
            _, value = await container.kv.window_add(key, 0, None, limit.window_s)
            exceeded = value >= limit.limit_value
        else:
            continue
        if exceeded:
            out.append(
                Violation(
                    limit.id,
                    limit.name,
                    limit.metric,
                    limit.limit_value,
                    int(value or 0),
                    limit.on_exceed,
                )
            )
    return out


async def count_failure(container: Container, limits: list[UsageLimit], subject: Subject) -> None:
    for limit in limits:
        if limit.metric != "failed_attempts":
            continue
        part = applies(limit, subject)
        if part is not None:
            await container.kv.window_add(f"limit:{limit.id}:{part}", 1, None, limit.window_s)


async def count_bytes(
    container: Container, limits: list[UsageLimit], subject: Subject, amount: int
) -> None:
    if amount <= 0:
        return
    for limit in limits:
        if limit.metric != "data_transfer_bytes":
            continue
        part = applies(limit, subject)
        if part is not None:
            await container.kv.window_add(f"limit:{limit.id}:{part}", amount, None, limit.window_s)
