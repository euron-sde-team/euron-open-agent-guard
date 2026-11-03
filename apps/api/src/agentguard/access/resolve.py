"""What an agent is granted: its roles (with inheritance) and their permissions.

An agent's roles are the roles bound to its organisation, to its project and to the agent
itself; each role brings the roles it inherits. The result is cached per process under the
policy generation, so a changed permission applies on the next decision on every replica.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from agentguard.access.models import AgentRole, Permission, Resource, RoleBinding
from agentguard.core.container import Container
from agentguard.policies import engine, expr
from agentguard.policies.service import generation

MAX_INHERIT_DEPTH = 10


@dataclass(frozen=True, slots=True)
class Granted:
    roles: list[str]
    grants: list[engine.Grant]


_cache: dict[tuple[uuid.UUID, uuid.UUID], tuple[int, Granted]] = {}


async def for_agent(
    container: Container,
    session: AsyncSession,
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    agent_id: uuid.UUID,
    gen: int | None = None,
) -> Granted:
    gen = await generation(container, org_id) if gen is None else gen
    key = (org_id, agent_id)
    hit = _cache.get(key)
    if hit is not None and gen >= 0 and hit[0] == gen:
        return hit[1]
    bound = (
        await session.scalars(
            select(RoleBinding.role_id).where(
                RoleBinding.org_id == org_id,
                or_(
                    (RoleBinding.subject_type == "org") & (RoleBinding.subject_id == org_id),
                    (RoleBinding.subject_type == "project")
                    & (RoleBinding.subject_id == project_id),
                    (RoleBinding.subject_type == "agent") & (RoleBinding.subject_id == agent_id),
                ),
            )
        )
    ).all()
    all_roles = {
        r.name: r
        for r in (await session.scalars(select(AgentRole).where(AgentRole.org_id == org_id))).all()
    }
    by_id = {r.id: r for r in all_roles.values()}
    names: set[str] = set()
    frontier = [by_id[rid].name for rid in bound if rid in by_id]
    depth = 0
    while frontier and depth <= MAX_INHERIT_DEPTH:
        nxt: list[str] = []
        for name in frontier:
            if name in names or name not in all_roles:
                continue
            names.add(name)
            nxt.extend(all_roles[name].inherits)
        frontier = nxt
        depth += 1
    role_ids = [all_roles[n].id for n in names]
    perms = (
        (await session.scalars(select(Permission).where(Permission.role_id.in_(role_ids)))).all()
        if role_ids
        else []
    )
    id_to_name = {all_roles[n].id: n for n in names}
    grants: list[engine.Grant] = []
    for p in perms:
        condition = None
        if p.condition:
            try:
                condition = expr.parse(p.condition)
            except expr.ExprError:
                continue  # rejected on save; a broken row never grants
        grants.append(
            engine.Grant(
                role=id_to_name.get(p.role_id, "?"),
                tool=p.tool,
                actions=tuple(p.actions),
                resource=p.resource or "*",
                condition=condition,
            )
        )
    result = Granted(sorted(names), grants)
    if gen >= 0:
        if len(_cache) > 20_000:
            _cache.clear()
        _cache[key] = (gen, result)
    return result


def check_inheritance(roles: dict[str, list[str]], name: str, inherits: list[str]) -> None:
    """Raise ValueError when inherits names an unknown role or creates a cycle."""
    graph = {**roles, name: inherits}
    for parent in inherits:
        if parent not in graph:
            raise ValueError(f"Unknown role {parent}")
    seen: set[str] = set()

    def visit(node: str, path: tuple[str, ...]) -> None:
        if node in path:
            raise ValueError(f"Roles may not inherit in a cycle: {' -> '.join((*path, node))}")
        if node in seen:
            return
        seen.add(node)
        for child in graph.get(node, []):
            visit(child, (*path, node))

    visit(name, ())


async def find_resource(session: AsyncSession, org_id: uuid.UUID, key: str) -> Resource | None:
    """The registered resource for a key: an exact match, else the most specific pattern."""
    if not key:
        return None
    exact = await session.scalar(
        select(Resource).where(Resource.org_id == org_id, Resource.key == key)
    )
    if exact is not None:
        return exact
    patterns = (
        await session.scalars(
            select(Resource).where(Resource.org_id == org_id, Resource.key.contains("*"))
        )
    ).all()
    best: Resource | None = None
    for res in patterns:
        if engine.glob([res.key], key) and (best is None or len(res.key) > len(best.key)):
            best = res
    return best
