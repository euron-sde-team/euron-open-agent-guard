"""Organisations: creation with safe defaults, settings, projects, the kill switch.

Settings documents are validated by their Pydantic models on every read and write, so a
document written by an older version gains new fields with their defaults instead of
failing. The AI-assisted detection key is sealed and never returned.
"""

from __future__ import annotations

import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from agentguard.audit.service import Actor, audit
from agentguard.core import events
from agentguard.core.container import Container
from agentguard.core.errors import AppError, ConflictError, NotFoundError
from agentguard.org.models import Org, OrgSettings, Project
from agentguard.org.schemas import (
    Detection,
    Enforcement,
    KillSwitch,
    Notifications,
    OrgSettingsOut,
    OrgSettingsUpdate,
    ProjectIn,
    ProjectOut,
    ProjectUpdate,
    Retention,
    ThreatResponses,
)

KEY_CONTEXT = "org:{org_id}:ai_api_key"
# The kill switch must bite within a second on every replica: settings are cached only
# this long per process.
SETTINGS_TTL_S = 1.0


@dataclass(frozen=True)
class Bundle:
    org_id: uuid.UUID
    enforcement: Enforcement
    kill_switch: KillSwitch
    detection: Detection
    threat_responses: ThreatResponses
    retention: Retention
    notifications: Notifications
    ai_key_sealed: bytes | None


def slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:40]
    return slug or "org"


async def unique_slug(session: AsyncSession, name: str) -> str:
    base = slugify(name)
    slug = base
    while await session.scalar(select(Org.id).where(Org.slug == slug)) is not None:
        slug = f"{base}-{secrets.token_hex(2)}"
    return slug


async def create_org(session: AsyncSession, name: str) -> tuple[Org, Project]:
    """An organisation that is safe and usable at once: default settings (enforce, deny by
    default), a default project, a network policy that allows only public addresses, and
    the built-in guard policies."""
    from agentguard.network.models import NetworkPolicy
    from agentguard.policies import service as policies
    from agentguard.policies.builtin import BUILTIN

    org = Org(name=name, slug=await unique_slug(session, name))
    session.add(org)
    await session.flush()
    session.add(
        OrgSettings(
            org_id=org.id,
            enforcement=Enforcement().model_dump(mode="json"),
            kill_switch=KillSwitch().model_dump(mode="json"),
            detection=Detection().model_dump(mode="json"),
            threat_responses=ThreatResponses().model_dump(mode="json"),
            retention=Retention().model_dump(mode="json"),
            notifications=Notifications().model_dump(mode="json"),
        )
    )
    project = Project(org_id=org.id, name="Default", slug="default", environment="production")
    session.add(project)
    session.add(
        NetworkPolicy(
            org_id=org.id,
            name="public-internet",
            description="Public internet addresses only. Private networks and cloud metadata are always refused.",
            rules=[],
            default_action="allow",
            is_default=True,
        )
    )
    await session.flush()
    for source in BUILTIN:
        await policies.create_builtin(session, org.id, source)
    return org, project


_cache: dict[uuid.UUID, tuple[float, Bundle]] = {}


def forget(org_id: uuid.UUID) -> None:
    _cache.pop(org_id, None)


async def load(session: AsyncSession, org_id: uuid.UUID, *, fresh: bool = False) -> Bundle:
    import time

    now = time.monotonic()
    hit = _cache.get(org_id)
    if hit is not None and not fresh and now - hit[0] < SETTINGS_TTL_S:
        return hit[1]
    row = await session.get(OrgSettings, org_id)
    if row is None:
        raise NotFoundError("Organisation not found")
    bundle = Bundle(
        org_id=org_id,
        enforcement=Enforcement.model_validate(row.enforcement or {}),
        kill_switch=KillSwitch.model_validate(row.kill_switch or {}),
        detection=Detection.model_validate(row.detection or {}),
        threat_responses=ThreatResponses.model_validate(row.threat_responses or {}),
        retention=Retention.model_validate(row.retention or {}),
        notifications=Notifications.model_validate(row.notifications or {}),
        ai_key_sealed=row.ai_api_key_sealed,
    )
    if len(_cache) > 10_000:
        _cache.clear()
    _cache[org_id] = (now, bundle)
    return bundle


def to_out(bundle: Bundle) -> OrgSettingsOut:
    return OrgSettingsOut(
        enforcement=bundle.enforcement,
        kill_switch=bundle.kill_switch,
        detection=bundle.detection,
        ai_api_key_set=bundle.ai_key_sealed is not None,
        threat_responses=bundle.threat_responses,
        retention=bundle.retention,
        notifications=bundle.notifications,
    )


async def unseal_ai_key(container: Container, bundle: Bundle) -> str | None:
    if bundle.ai_key_sealed is None:
        return None
    return await container.sealer.open(
        bundle.ai_key_sealed, KEY_CONTEXT.format(org_id=bundle.org_id)
    )


async def update_settings(
    container: Container, session: AsyncSession, actor: Actor, patch: OrgSettingsUpdate
) -> Bundle:
    row = await session.get(OrgSettings, actor.org_id)
    if row is None:
        raise NotFoundError("Organisation not found")
    changed: list[str] = []
    if patch.enforcement is not None:
        if patch.enforcement.default_decision == "allow" and patch.enforcement.mode != "audit":
            raise AppError(
                "A default of allow is only possible in audit mode; in enforce mode unknown actions are denied",
                code="unsafe_default",
            )
        if not patch.enforcement.require_registered_tools and patch.enforcement.mode != "audit":
            raise AppError(
                "Unregistered tools can only be tolerated in audit mode", code="unsafe_default"
            )
        row.enforcement = patch.enforcement.model_dump(mode="json")
        changed.append("enforcement")
    if patch.detection is not None:
        row.detection = patch.detection.model_dump(mode="json")
        changed.append("detection")
    if patch.threat_responses is not None:
        row.threat_responses = patch.threat_responses.model_dump(mode="json")
        changed.append("threat_responses")
    if patch.retention is not None:
        row.retention = patch.retention.model_dump(mode="json")
        changed.append("retention")
    if patch.notifications is not None:
        row.notifications = patch.notifications.model_dump(mode="json")
        changed.append("notifications")
    if patch.ai_api_key is not None:
        row.ai_api_key_sealed = (
            await container.sealer.seal(patch.ai_api_key, KEY_CONTEXT.format(org_id=actor.org_id))
            if patch.ai_api_key
            else None
        )
        changed.append("ai_api_key")
    audit(session, actor, "settings.updated", "org", actor.org_id, sections=changed)
    await session.commit()
    forget(actor.org_id)
    return await load(session, actor.org_id, fresh=True)


async def set_kill_switch(
    session: AsyncSession, actor: Actor, active: bool, reason: str
) -> KillSwitch:
    row = await session.get(OrgSettings, actor.org_id)
    if row is None:
        raise NotFoundError("Organisation not found")
    if active and not reason.strip():
        raise AppError("Say why you are stopping every agent", code="reason_required")
    switch = KillSwitch(active=active, reason=reason, by=actor.label, at=datetime.now(UTC))
    row.kill_switch = switch.model_dump(mode="json")
    audit(
        session,
        actor,
        "kill_switch.on" if active else "kill_switch.off",
        "org",
        actor.org_id,
        reason=reason,
    )
    events.emit(session, f"org:{actor.org_id}", {"type": "kill_switch", "active": active})
    forget(actor.org_id)
    # Every replica re-reads settings within SETTINGS_TTL_S; publishing also wakes dashboards.
    return switch


async def list_projects(session: AsyncSession, org_id: uuid.UUID) -> list[ProjectOut]:
    from agentguard.identity.models import Agent

    counts = dict(
        (
            await session.execute(
                select(Agent.project_id, func.count())
                .where(Agent.org_id == org_id)
                .group_by(Agent.project_id)
            )
        ).all()
    )
    rows = (
        await session.scalars(
            select(Project).where(Project.org_id == org_id).order_by(Project.name)
        )
    ).all()
    return [
        ProjectOut(
            id=p.id,
            name=p.name,
            slug=p.slug,
            description=p.description,
            environment=p.environment,
            agents=int(counts.get(p.id, 0)),
            created_at=p.created_at,
        )
        for p in rows
    ]


async def create_project(session: AsyncSession, actor: Actor, body: ProjectIn) -> Project:
    exists = await session.scalar(
        select(Project.id).where(Project.org_id == actor.org_id, Project.slug == body.slug)
    )
    if exists:
        raise ConflictError(f"A project with the slug {body.slug} exists", code="duplicate")
    project = Project(org_id=actor.org_id, **body.model_dump())
    session.add(project)
    await session.flush()
    audit(session, actor, "project.created", "project", project.id, slug=body.slug)
    return project


async def get_project(session: AsyncSession, org_id: uuid.UUID, project_id: uuid.UUID) -> Project:
    project = await session.get(Project, project_id)
    if project is None or project.org_id != org_id:
        raise NotFoundError("Project not found")
    return project


async def update_project(
    session: AsyncSession, actor: Actor, project: Project, body: ProjectUpdate
) -> Project:
    for key, value in body.model_dump(exclude_none=True).items():
        setattr(project, key, value)
    audit(
        session,
        actor,
        "project.updated",
        "project",
        project.id,
        **body.model_dump(exclude_none=True),
    )
    return project
