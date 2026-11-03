"""Agent roles, their permissions and bindings, and protected resources."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select

from agentguard.access.models import (
    BINDING_SUBJECTS,
    SENSITIVITIES,
    AgentRole,
    Permission,
    Resource,
    RoleBinding,
)
from agentguard.access.resolve import check_inheritance
from agentguard.audit.service import audit
from agentguard.auth.dependencies import StaffRead, StaffWrite
from agentguard.core.deps import ContainerDep, SessionDep
from agentguard.core.errors import AppError, ConflictError, NotFoundError
from agentguard.identity.models import Agent
from agentguard.org.models import Project
from agentguard.policies import expr
from agentguard.policies.service import bump

router = APIRouter(prefix="/api/v1", tags=["access control"])


class PermissionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool: str = Field(..., min_length=1, max_length=200)
    actions: list[str] = Field(default_factory=list, max_length=50)
    resource: str = Field("*", max_length=300)
    condition: str = Field("", max_length=1000)


class PermissionOut(PermissionIn):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID


class RoleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(..., min_length=2, max_length=64, pattern=r"^[a-z0-9][a-z0-9_-]*$")
    description: str = Field("", max_length=500)
    inherits: list[str] = Field(default_factory=list, max_length=20)
    permissions: list[PermissionIn] = Field(default_factory=list, max_length=200)


class RoleUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    description: str | None = Field(None, max_length=500)
    inherits: list[str] | None = None
    permissions: list[PermissionIn] | None = None


class BindingOut(BaseModel):
    id: uuid.UUID
    subject_type: str
    subject_id: uuid.UUID
    subject: str


class RoleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    name: str
    description: str
    inherits: list[str]
    created_at: datetime
    permissions: list[PermissionOut] = Field(default_factory=list)
    bindings: list[BindingOut] = Field(default_factory=list)


class BindingIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: str
    subject_type: str = Field(..., pattern="^(" + "|".join(BINDING_SUBJECTS) + ")$")
    subject_id: uuid.UUID | None = Field(None, description="Project or agent id; omitted for org")


class ResourceIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key: str = Field(..., min_length=3, max_length=300, pattern=r"^[A-Za-z0-9_.-]+:[^\s]+$")
    name: str = Field(..., min_length=1, max_length=200)
    project_id: uuid.UUID | None = None
    sensitivity: str = Field("internal", pattern="^(" + "|".join(SENSITIVITIES) + ")$")
    environment: str = Field("production", pattern="^(development|staging|production)$")
    data_classes: list[str] = Field(default_factory=list, max_length=20)
    tags: dict[str, str | int | bool] = Field(default_factory=dict)


class ResourceUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(None, max_length=200)
    project_id: uuid.UUID | None = None
    sensitivity: str | None = Field(None, pattern="^(" + "|".join(SENSITIVITIES) + ")$")
    environment: str | None = Field(None, pattern="^(development|staging|production)$")
    data_classes: list[str] | None = None
    tags: dict[str, str | int | bool] | None = None


class ResourceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    key: str
    name: str
    type: str
    project_id: uuid.UUID | None
    sensitivity: str
    environment: str
    data_classes: list[str]
    tags: dict[str, Any]
    created_at: datetime


def _check_permission(p: PermissionIn) -> None:
    if p.condition:
        try:
            expr.parse(p.condition)
        except expr.ExprError as exc:
            raise AppError(f"Condition for {p.tool}: {exc}", code="invalid_condition") from exc


async def _roles_out(
    session: SessionDep, org_id: uuid.UUID, rows: list[AgentRole]
) -> list[RoleOut]:
    ids = [r.id for r in rows]
    perms = (
        (await session.scalars(select(Permission).where(Permission.role_id.in_(ids)))).all()
        if ids
        else []
    )
    bindings = (
        (await session.scalars(select(RoleBinding).where(RoleBinding.role_id.in_(ids)))).all()
        if ids
        else []
    )
    agents = dict(
        (await session.execute(select(Agent.id, Agent.slug).where(Agent.org_id == org_id))).all()
    )
    projects = dict(
        (
            await session.execute(select(Project.id, Project.slug).where(Project.org_id == org_id))
        ).all()
    )
    out = []
    for r in rows:
        item = RoleOut.model_validate(r)
        item.permissions = [PermissionOut.model_validate(p) for p in perms if p.role_id == r.id]
        item.bindings = [
            BindingOut(
                id=b.id,
                subject_type=b.subject_type,
                subject_id=b.subject_id,
                subject="whole organisation"
                if b.subject_type == "org"
                else (agents if b.subject_type == "agent" else projects).get(b.subject_id, "?"),
            )
            for b in bindings
            if b.role_id == r.id
        ]
        out.append(item)
    return out


async def _role(session: SessionDep, org_id: uuid.UUID, role_id: uuid.UUID) -> AgentRole:
    role = await session.get(AgentRole, role_id)
    if role is None or role.org_id != org_id:
        raise NotFoundError("Role not found")
    return role


async def _check_inherits(
    session: SessionDep, org_id: uuid.UUID, name: str, inherits: list[str]
) -> None:
    roles = {
        r.name: list(r.inherits)
        for r in (await session.scalars(select(AgentRole).where(AgentRole.org_id == org_id))).all()
    }
    try:
        check_inheritance(roles, name, inherits)
    except ValueError as exc:
        raise AppError(str(exc), code="invalid_inheritance") from exc


@router.get(
    "/roles", response_model=list[RoleOut], summary="Agent roles with permissions and bindings"
)
async def list_roles(actor: StaffRead, session: SessionDep) -> list[RoleOut]:
    rows = (
        await session.scalars(
            select(AgentRole).where(AgentRole.org_id == actor.org_id).order_by(AgentRole.name)
        )
    ).all()
    return await _roles_out(session, actor.org_id, list(rows))


@router.post("/roles", response_model=RoleOut, status_code=201, summary="Create a role")
async def create_role(
    body: RoleIn, actor: StaffWrite, container: ContainerDep, session: SessionDep
) -> RoleOut:
    if await session.scalar(
        select(AgentRole.id).where(AgentRole.org_id == actor.org_id, AgentRole.name == body.name)
    ):
        raise ConflictError(f"A role named {body.name} exists", code="duplicate")
    await _check_inherits(session, actor.org_id, body.name, body.inherits)
    for p in body.permissions:
        _check_permission(p)
    role = AgentRole(
        org_id=actor.org_id, name=body.name, description=body.description, inherits=body.inherits
    )
    session.add(role)
    await session.flush()
    for p in body.permissions:
        session.add(Permission(org_id=actor.org_id, role_id=role.id, **p.model_dump()))
    audit(
        session,
        actor,
        "role.created",
        "role",
        role.id,
        name=role.name,
        permissions=len(body.permissions),
    )
    await bump(container, actor.org_id)
    await session.commit()
    return (await _roles_out(session, actor.org_id, [role]))[0]


@router.put(
    "/roles/{role_id}",
    response_model=RoleOut,
    summary="Change a role (permissions given replace the old ones)",
)
async def update_role(
    role_id: uuid.UUID,
    body: RoleUpdate,
    actor: StaffWrite,
    container: ContainerDep,
    session: SessionDep,
) -> RoleOut:
    role = await _role(session, actor.org_id, role_id)
    if body.inherits is not None:
        await _check_inherits(session, actor.org_id, role.name, body.inherits)
        role.inherits = body.inherits
    if body.description is not None:
        role.description = body.description
    if body.permissions is not None:
        for p in body.permissions:
            _check_permission(p)
        for old in (
            await session.scalars(select(Permission).where(Permission.role_id == role.id))
        ).all():
            await session.delete(old)
        for p in body.permissions:
            session.add(Permission(org_id=actor.org_id, role_id=role.id, **p.model_dump()))
    audit(
        session,
        actor,
        "role.updated",
        "role",
        role.id,
        permissions=len(body.permissions) if body.permissions is not None else None,
    )
    await bump(container, actor.org_id)
    await session.commit()
    return (await _roles_out(session, actor.org_id, [role]))[0]


@router.delete(
    "/roles/{role_id}",
    status_code=204,
    summary="Delete a role (its bindings and permissions go too)",
)
async def delete_role(
    role_id: uuid.UUID, actor: StaffWrite, container: ContainerDep, session: SessionDep
) -> Response:
    role = await _role(session, actor.org_id, role_id)
    users = (await session.scalars(select(AgentRole).where(AgentRole.org_id == actor.org_id))).all()
    heirs = [r.name for r in users if role.name in r.inherits]
    if heirs:
        raise AppError(f"Roles {', '.join(heirs)} inherit from {role.name}", code="in_use")
    audit(session, actor, "role.deleted", "role", role.id, name=role.name)
    await session.delete(role)
    await bump(container, actor.org_id)
    await session.commit()
    return Response(status_code=204)


@router.post(
    "/role-bindings",
    response_model=RoleOut,
    status_code=201,
    summary="Bind a role to the organisation, a project or an agent",
)
async def bind(
    body: BindingIn, actor: StaffWrite, container: ContainerDep, session: SessionDep
) -> RoleOut:
    role = await session.scalar(
        select(AgentRole).where(AgentRole.org_id == actor.org_id, AgentRole.name == body.role)
    )
    if role is None:
        raise NotFoundError(f"No role named {body.role}")
    subject_id = actor.org_id if body.subject_type == "org" else body.subject_id
    if subject_id is None:
        raise AppError(
            "subject_id is required for project and agent bindings", code="subject_required"
        )
    model = (
        Project
        if body.subject_type == "project"
        else Agent
        if body.subject_type == "agent"
        else None
    )
    if model is not None:
        row: Project | Agent | None = await session.get(model, subject_id)
        if row is None or row.org_id != actor.org_id:
            raise NotFoundError(f"{body.subject_type.capitalize()} not found")
    exists = await session.scalar(
        select(RoleBinding.id).where(
            RoleBinding.role_id == role.id,
            RoleBinding.subject_type == body.subject_type,
            RoleBinding.subject_id == subject_id,
        )
    )
    if not exists:
        session.add(
            RoleBinding(
                org_id=actor.org_id,
                role_id=role.id,
                subject_type=body.subject_type,
                subject_id=subject_id,
            )
        )
        audit(
            session,
            actor,
            "role.bound",
            "role",
            role.id,
            subject_type=body.subject_type,
            subject_id=str(subject_id),
        )
        await bump(container, actor.org_id)
        await session.commit()
    return (await _roles_out(session, actor.org_id, [role]))[0]


@router.delete("/role-bindings/{binding_id}", status_code=204, summary="Remove a binding")
async def unbind(
    binding_id: uuid.UUID, actor: StaffWrite, container: ContainerDep, session: SessionDep
) -> Response:
    binding = await session.get(RoleBinding, binding_id)
    if binding is None or binding.org_id != actor.org_id:
        raise NotFoundError("Binding not found")
    audit(
        session,
        actor,
        "role.unbound",
        "role",
        binding.role_id,
        subject_type=binding.subject_type,
        subject_id=str(binding.subject_id),
    )
    await session.delete(binding)
    await bump(container, actor.org_id)
    await session.commit()
    return Response(status_code=204)


@router.get("/resources", response_model=list[ResourceOut], summary="Protected resources")
async def list_resources(actor: StaffRead, session: SessionDep) -> list[Resource]:
    return list(
        (
            await session.scalars(
                select(Resource)
                .where(Resource.org_id == actor.org_id)
                .order_by(Resource.key)
                .limit(2000)
            )
        ).all()
    )


@router.post(
    "/resources",
    response_model=ResourceOut,
    status_code=201,
    summary="Register a resource (a key or a pattern like customer:*)",
)
async def create_resource(
    body: ResourceIn, actor: StaffWrite, container: ContainerDep, session: SessionDep
) -> Resource:
    if await session.scalar(
        select(func.count())
        .select_from(Resource)
        .where(Resource.org_id == actor.org_id, Resource.key == body.key)
    ):
        raise ConflictError(f"{body.key} is already registered", code="duplicate")
    resource = Resource(org_id=actor.org_id, type=body.key.split(":", 1)[0], **body.model_dump())
    session.add(resource)
    await session.flush()
    await bump(container, actor.org_id)
    audit(
        session,
        actor,
        "resource.created",
        "resource",
        resource.id,
        key=resource.key,
        sensitivity=resource.sensitivity,
    )
    await session.commit()
    return resource


@router.patch("/resources/{resource_id}", response_model=ResourceOut, summary="Change a resource")
async def update_resource(
    resource_id: uuid.UUID,
    body: ResourceUpdate,
    actor: StaffWrite,
    container: ContainerDep,
    session: SessionDep,
) -> Resource:
    resource = await session.get(Resource, resource_id)
    if resource is None or resource.org_id != actor.org_id:
        raise NotFoundError("Resource not found")
    changes = body.model_dump(exclude_unset=True)
    for key, value in changes.items():
        setattr(resource, key, value)
    await bump(container, actor.org_id)
    audit(session, actor, "resource.updated", "resource", resource.id, fields=sorted(changes))
    await session.commit()
    return resource


@router.delete("/resources/{resource_id}", status_code=204, summary="Forget a resource")
async def delete_resource(
    resource_id: uuid.UUID, actor: StaffWrite, container: ContainerDep, session: SessionDep
) -> Response:
    resource = await session.get(Resource, resource_id)
    if resource is None or resource.org_id != actor.org_id:
        raise NotFoundError("Resource not found")
    await bump(container, actor.org_id)
    audit(session, actor, "resource.deleted", "resource", resource.id, key=resource.key)
    await session.delete(resource)
    await session.commit()
    return Response(status_code=204)
