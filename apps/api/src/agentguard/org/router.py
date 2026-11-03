"""The organisation, its settings and its projects."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Request
from pydantic import BaseModel
from sqlalchemy import func, select

from agentguard.auth.dependencies import CurrentUser, OrgAdmin, StaffRead, StaffWrite
from agentguard.core.deps import ContainerDep, SessionDep
from agentguard.core.errors import NotFoundError, PermissionDeniedError
from agentguard.org import service
from agentguard.org.models import Org
from agentguard.org.schemas import (
    OrgOut,
    OrgSettingsOut,
    OrgSettingsUpdate,
    ProjectIn,
    ProjectOut,
    ProjectUpdate,
)
from agentguard.policies.service import bump

router = APIRouter(prefix="/api/v1", tags=["organisation"])


@router.get("/org", response_model=OrgOut, summary="This organisation")
async def get_org(actor: StaffRead, session: SessionDep) -> Org:
    org = await session.get(Org, actor.org_id)
    if org is None:
        raise NotFoundError("Organisation not found")
    return org


@router.get("/settings", response_model=OrgSettingsOut, summary="Security settings")
async def get_settings(actor: StaffRead, session: SessionDep) -> OrgSettingsOut:
    return service.to_out(await service.load(session, actor.org_id, fresh=True))


@router.patch("/settings", response_model=OrgSettingsOut, summary="Change security settings")
async def update_settings(
    body: OrgSettingsUpdate, actor: OrgAdmin, container: ContainerDep, session: SessionDep
) -> OrgSettingsOut:
    return service.to_out(await service.update_settings(container, session, actor, body))


@router.get("/projects", response_model=list[ProjectOut], summary="Projects")
async def list_projects(actor: StaffRead, session: SessionDep) -> list[ProjectOut]:
    return await service.list_projects(session, actor.org_id)


@router.post("/projects", response_model=ProjectOut, status_code=201, summary="Create a project")
async def create_project(
    body: ProjectIn, actor: StaffWrite, container: ContainerDep, session: SessionDep
) -> ProjectOut:
    project = await service.create_project(session, actor, body)
    await session.commit()
    await bump(container, actor.org_id)
    return next(p for p in await service.list_projects(session, actor.org_id) if p.id == project.id)


@router.patch("/projects/{project_id}", response_model=ProjectOut, summary="Change a project")
async def update_project(
    project_id: uuid.UUID,
    body: ProjectUpdate,
    actor: StaffWrite,
    container: ContainerDep,
    session: SessionDep,
) -> ProjectOut:
    project = await service.get_project(session, actor.org_id, project_id)
    await service.update_project(session, actor, project, body)
    await session.commit()
    await bump(container, actor.org_id)
    return next(p for p in await service.list_projects(session, actor.org_id) if p.id == project.id)


class InstallationOrg(BaseModel):
    id: uuid.UUID
    name: str
    slug: str
    users: int


@router.get(
    "/installation/orgs",
    response_model=list[InstallationOrg],
    summary="Every organisation on this installation (global administrators)",
)
async def installation_orgs(
    request: Request, user: CurrentUser, session: SessionDep
) -> list[InstallationOrg]:
    from agentguard.users.models import User

    if not user.is_global_admin:
        raise PermissionDeniedError("This needs a global administrator", code="global_admin_only")
    counts = dict(
        (await session.execute(select(User.org_id, func.count()).group_by(User.org_id))).all()
    )
    rows = (await session.scalars(select(Org).order_by(Org.name))).all()
    return [
        InstallationOrg(id=o.id, name=o.name, slug=o.slug, users=int(counts.get(o.id, 0)))
        for o in rows
    ]
