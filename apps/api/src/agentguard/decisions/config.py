"""The configuration a decision reads, cached per organisation under the policy generation.

A decision needs the tool, the resources, the projects, the organisation's slug, its risk
rules, limits and integrations. They change rarely and are read on every action, so they
are loaded once per organisation and **generation** (the counter every policy, permission,
tool, resource, limit, risk rule and integration change bumps, on every replica, through the
KV store). A change applies to the next decision anywhere; an unreachable KV store disables
the cache rather than serving stale configuration.

Rows are loaded through the caller's session and detached (read-only snapshots).
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agentguard.access.models import Resource
from agentguard.core.container import Container
from agentguard.integrations.models import Integration
from agentguard.limits.models import UsageLimit
from agentguard.org.models import Org, Project
from agentguard.policies import engine, expr
from agentguard.policies.service import generation
from agentguard.risk import engine as risk_engine
from agentguard.risk.models import RiskRule
from agentguard.tools.models import Tool


@dataclass
class OrgConfig:
    # The policy generation this snapshot belongs to (shared with the other caches).
    gen: int
    org_slug: str
    tools: dict[str, Tool]
    resources: dict[str, Resource]
    resource_patterns: list[Resource]
    projects: dict[uuid.UUID, Project]
    risk_rules: list[risk_engine.RiskRule]
    limits: list[UsageLimit]
    tokenshield: Integration | None
    opa: Integration | None
    extra: dict[str, Any] = field(default_factory=dict)

    def resource(self, key: str) -> Resource | None:
        """An exact match, else the most specific pattern."""
        if not key:
            return None
        exact = self.resources.get(key)
        if exact is not None:
            return exact
        best: Resource | None = None
        for res in self.resource_patterns:
            if engine.glob([res.key], key) and (best is None or len(res.key) > len(best.key)):
                best = res
        return best


_cache: dict[uuid.UUID, tuple[int, OrgConfig]] = {}
_locks: dict[uuid.UUID, asyncio.Lock] = {}


async def load(container: Container, session: AsyncSession, org_id: uuid.UUID) -> OrgConfig:
    gen = await generation(container, org_id)
    hit = _cache.get(org_id)
    if hit is not None and gen >= 0 and hit[0] == gen:
        return hit[1]
    if gen < 0:
        # The KV store is unreachable: no caching, but still one load per request.
        return await _load(session, org_id, gen)
    # Single flight: on a miss, one request loads and the others wait for it, so a burst
    # after a change does not open a second connection per request and drain the pool.
    async with _locks.setdefault(org_id, asyncio.Lock()):
        hit = _cache.get(org_id)
        if hit is not None and gen >= 0 and hit[0] >= gen:
            return hit[1]
        return await _load(session, org_id, gen)


async def _load(session: AsyncSession, org_id: uuid.UUID, gen: int) -> OrgConfig:
    # The caller's session: a request already holds a connection, so loading through a
    # second one could wait forever on a pool that its waiting peers have filled.
    slug = await session.scalar(select(Org.slug).where(Org.id == org_id))
    tools = {
        t.name: t for t in (await session.scalars(select(Tool).where(Tool.org_id == org_id))).all()
    }
    resources = list(
        (await session.scalars(select(Resource).where(Resource.org_id == org_id))).all()
    )
    projects = {
        p.id: p
        for p in (await session.scalars(select(Project).where(Project.org_id == org_id))).all()
    }
    rules = []
    for r in (
        await session.scalars(
            select(RiskRule).where(RiskRule.org_id == org_id, RiskRule.enabled.is_(True))
        )
    ).all():
        try:
            rules.append(risk_engine.RiskRule(r.name, expr.parse(r.condition), r.points))
        except expr.ExprError:
            continue
    limits = list(
        (
            await session.scalars(
                select(UsageLimit).where(UsageLimit.org_id == org_id, UsageLimit.enabled.is_(True))
            )
        ).all()
    )
    integrations = {
        i.kind: i
        for i in (
            await session.scalars(
                select(Integration).where(
                    Integration.org_id == org_id, Integration.enabled.is_(True)
                )
            )
        ).all()
    }
    for row in [*tools.values(), *resources, *projects.values(), *limits, *integrations.values()]:
        session.expunge(row)  # read-only snapshots, shared across requests
    config = OrgConfig(
        gen=gen,
        org_slug=slug or "",
        tools=tools,
        resources={r.key: r for r in resources if "*" not in r.key},
        resource_patterns=[r for r in resources if "*" in r.key],
        projects=projects,
        risk_rules=rules,
        limits=limits,
        tokenshield=integrations.get("tokenshield"),
        opa=integrations.get("opa"),
    )
    if gen >= 0:
        if len(_cache) > 5000:
            _cache.clear()
        _cache[org_id] = (gen, config)
    return config
