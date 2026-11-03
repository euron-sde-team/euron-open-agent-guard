"""Policy lifecycle: create, version, activate, roll back, disable, simulate.

Active policies and agent permissions are cached per process for each organisation under a
**generation** number kept in the KV store. Every change bumps the generation in the same
request, so the next decision on any replica reloads them: a deactivated policy stops
applying immediately, not after a TTL.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agentguard.audit.service import Actor, audit, system_actor
from agentguard.core.container import Container
from agentguard.core.errors import AppError, ConflictError, NotFoundError
from agentguard.policies import engine
from agentguard.policies.dsl import PolicyError, compile_policy
from agentguard.policies.models import Policy, PolicyVersion

GEN_KEY = "policy-gen:{org_id}"
_cache: dict[uuid.UUID, tuple[int, list[engine.ActivePolicy]]] = {}


async def generation(container: Container, org_id: uuid.UUID) -> int:
    try:
        raw = await container.kv.get(GEN_KEY.format(org_id=org_id))
    except Exception:
        return -1  # cache unreachable: never trust the process cache
    return int(raw or b"0")


async def bump(container: Container, org_id: uuid.UUID) -> None:
    _cache.pop(org_id, None)
    try:
        await container.kv.incr(GEN_KEY.format(org_id=org_id))
    except Exception:
        return


async def active_policies(
    container: Container, session: AsyncSession, org_id: uuid.UUID, gen: int | None = None
) -> list[engine.ActivePolicy]:
    gen = await generation(container, org_id) if gen is None else gen
    hit = _cache.get(org_id)
    if hit is not None and gen >= 0 and hit[0] == gen:
        return hit[1]
    rows = (
        await session.execute(
            select(Policy, PolicyVersion)
            .join(
                PolicyVersion,
                (PolicyVersion.policy_id == Policy.id)
                & (PolicyVersion.version == Policy.active_version),
            )
            .where(Policy.org_id == org_id, Policy.status == "active")
        )
    ).all()
    loaded = [engine.ActivePolicy(str(p.id), p.name, v.version, v.compiled) for p, v in rows]
    if gen >= 0:
        if len(_cache) > 5000:
            _cache.clear()
        _cache[org_id] = (gen, loaded)
    return loaded


def _compile(source: str) -> dict[str, Any]:
    try:
        return compile_policy(source)
    except PolicyError as exc:
        raise AppError(str(exc), code="invalid_policy") from exc


async def get(session: AsyncSession, org_id: uuid.UUID, policy_id: uuid.UUID) -> Policy:
    policy = await session.get(Policy, policy_id)
    if policy is None or policy.org_id != org_id:
        raise NotFoundError("Policy not found")
    return policy


async def version_of(session: AsyncSession, policy: Policy, version: int) -> PolicyVersion:
    row = await session.scalar(
        select(PolicyVersion).where(
            PolicyVersion.policy_id == policy.id, PolicyVersion.version == version
        )
    )
    if row is None:
        raise NotFoundError(f"Version {version} not found")
    return row


async def create(
    container: Container,
    session: AsyncSession,
    actor: Actor,
    source: str,
    *,
    activate: bool,
    comment: str = "",
    builtin: bool = False,
) -> tuple[Policy, PolicyVersion]:
    compiled = _compile(source)
    exists = await session.scalar(
        select(Policy.id).where(Policy.org_id == actor.org_id, Policy.name == compiled["name"])
    )
    if exists:
        raise ConflictError(
            f"A policy named {compiled['name']} exists; save a new version of it", code="duplicate"
        )
    policy = Policy(
        org_id=actor.org_id,
        name=compiled["name"],
        description=compiled["description"],
        builtin=builtin,
        latest_version=1,
        created_by=actor.id if actor.kind == "user" else None,
    )
    session.add(policy)
    await session.flush()
    version = PolicyVersion(
        org_id=actor.org_id,
        policy_id=policy.id,
        version=1,
        source=source,
        compiled=compiled,
        comment=comment,
        created_by=actor.id if actor.kind == "user" else None,
    )
    session.add(version)
    audit(session, actor, "policy.created", "policy", policy.id, name=policy.name)
    if activate:
        await _activate(container, session, actor, policy, 1)
    return policy, version


async def create_builtin(session: AsyncSession, org_id: uuid.UUID, source: str) -> None:
    compiled = compile_policy(source)
    actor = system_actor(org_id, "agentguard")
    policy = Policy(
        org_id=org_id,
        name=compiled["name"],
        description=compiled["description"],
        builtin=True,
        status="active",
        active_version=1,
        latest_version=1,
    )
    session.add(policy)
    await session.flush()
    session.add(
        PolicyVersion(
            org_id=org_id,
            policy_id=policy.id,
            version=1,
            source=source,
            compiled=compiled,
            comment="Built in",
        )
    )
    audit(session, actor, "policy.created", "policy", policy.id, name=policy.name, builtin=True)


async def save_version(
    container: Container,
    session: AsyncSession,
    actor: Actor,
    policy: Policy,
    source: str,
    *,
    activate: bool,
    comment: str = "",
) -> PolicyVersion:
    compiled = _compile(source)
    if compiled["name"] != policy.name:
        raise AppError(
            f"The name in the document ({compiled['name']}) must stay {policy.name}; create a new policy to rename",
            code="name_changed",
        )
    # Lock the policy row so two editors cannot both write version n+1.
    locked = await session.scalar(select(Policy).where(Policy.id == policy.id).with_for_update())
    assert locked is not None
    locked.latest_version += 1
    locked.description = compiled["description"]
    version = PolicyVersion(
        org_id=policy.org_id,
        policy_id=policy.id,
        version=locked.latest_version,
        source=source,
        compiled=compiled,
        comment=comment,
        created_by=actor.id if actor.kind == "user" else None,
    )
    session.add(version)
    audit(session, actor, "policy.version_saved", "policy", policy.id, version=version.version)
    if activate:
        await _activate(container, session, actor, locked, version.version)
    return version


async def _activate(
    container: Container, session: AsyncSession, actor: Actor, policy: Policy, version: int
) -> None:
    previous = policy.active_version
    policy.active_version = version
    policy.status = "active"
    audit(
        session, actor, "policy.activated", "policy", policy.id, version=version, previous=previous
    )
    from agentguard.integrations.service import dispatch

    await dispatch(
        session,
        policy.org_id,
        "policy.activated",
        {
            "policy_id": str(policy.id),
            "name": policy.name,
            "version": version,
            "previous": previous,
        },
    )
    await bump(container, policy.org_id)


async def activate(
    container: Container, session: AsyncSession, actor: Actor, policy: Policy, version: int
) -> None:
    await version_of(session, policy, version)
    await _activate(container, session, actor, policy, version)


async def rollback(
    container: Container, session: AsyncSession, actor: Actor, policy: Policy
) -> int:
    """Activate the version before the active one."""
    if policy.active_version is None or policy.active_version <= 1:
        raise AppError("There is no earlier version to roll back to", code="no_previous_version")
    target = policy.active_version - 1
    await version_of(session, policy, target)
    policy.active_version = target
    policy.status = "active"
    audit(session, actor, "policy.rolled_back", "policy", policy.id, version=target)
    await bump(container, policy.org_id)
    return target


async def disable(
    container: Container, session: AsyncSession, actor: Actor, policy: Policy
) -> None:
    policy.status = "disabled"
    audit(session, actor, "policy.disabled", "policy", policy.id, version=policy.active_version)
    await bump(container, policy.org_id)


async def delete(container: Container, session: AsyncSession, actor: Actor, policy: Policy) -> None:
    if policy.builtin:
        raise AppError("Built-in policies can be disabled or edited, not deleted", code="builtin")
    audit(session, actor, "policy.deleted", "policy", policy.id, name=policy.name)
    await session.delete(policy)
    await bump(container, policy.org_id)


@dataclass(slots=True)
class SimulationResult:
    evaluated: int
    changed: list[dict[str, Any]]
    summary: dict[str, dict[str, int]]


async def simulate(
    container: Container,
    session: AsyncSession,
    org_id: uuid.UUID,
    *,
    source: str,
    replace_policy_id: uuid.UUID | None,
    days: int = 7,
    limit: int = 5000,
) -> SimulationResult:
    """Re-decide recorded decisions with a draft policy and report every one that changes.

    Each decision stored the (redacted) evaluation input it was made from, so the draft is
    evaluated against what really happened, alongside the other active policies (or in
    place of the policy being edited). Permissions are those recorded with the decision.
    """
    from agentguard.decisions.models import Decision

    draft = _compile(source)
    current = await active_policies(container, session, org_id)
    others = [p for p in current if replace_policy_id is None or p.id != str(replace_policy_id)]
    candidate = [*others, engine.ActivePolicy("draft", draft["name"], 0, draft)]
    since = datetime.now(UTC) - timedelta(days=max(1, min(days, 90)))
    rows = (
        await session.scalars(
            select(Decision)
            .where(Decision.org_id == org_id, Decision.at >= since, Decision.source != "egress")
            .order_by(Decision.at.desc())
            .limit(min(limit, 20_000))
        )
    ).all()
    changed: list[dict[str, Any]] = []
    summary: dict[str, dict[str, int]] = {}
    evaluated = 0
    for row in rows:
        data = row.context or {}
        if not data:
            continue
        evaluated += 1
        grants = [
            engine.Grant(
                role=g["role"],
                tool=g["tool"],
                actions=tuple(g["actions"]),
                resource=g["resource"],
                condition=g.get("condition"),
            )
            for g in (data.get("_grants") or [])
        ]
        default = data.get("_default", "deny")
        if data.get("_prechecked") or row.reason_code in ("approved", "agent_asked"):
            # Decided before policies ran, or by a person: a draft cannot change those.
            continue  # decided before policies ran (kill switch, invalid parameters...)
        outcome = engine.evaluate(candidate, grants, data, default=default)
        before = row.would_be
        after = outcome.decision
        if before != after:
            key = f"{before}->{after}"
            summary.setdefault(key, {"count": 0})["count"] += 1
            if len(changed) < 200:
                changed.append(
                    {
                        "decision_id": str(row.id),
                        "at": row.at.isoformat(),
                        "agent": (data.get("agent") or {}).get("slug"),
                        "tool": row.tool,
                        "action": row.action,
                        "resource": row.resource,
                        "before": before,
                        "after": after,
                        "reason": outcome.reason,
                    }
                )
    return SimulationResult(evaluated=evaluated, changed=changed, summary=summary)
