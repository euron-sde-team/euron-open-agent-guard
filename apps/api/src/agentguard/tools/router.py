"""The tool registry and the MCP server catalog."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Response
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import func, select

from agentguard.access.models import AgentRole, Permission
from agentguard.audit.service import audit
from agentguard.auth.dependencies import StaffRead, StaffWrite
from agentguard.core.deps import ContainerDep, SessionDep
from agentguard.core.errors import AppError, ConflictError, NotFoundError
from agentguard.decisions.models import Decision
from agentguard.mcp import catalog
from agentguard.mcp.models import McpServer, McpToolVersion
from agentguard.mcp.upstream import UpstreamError
from agentguard.policies.service import bump
from agentguard.tools.models import KINDS, RISK_LEVELS, Tool
from agentguard.tools.validation import check_constraints, check_schema, template_fields

router = APIRouter(prefix="/api/v1", tags=["tools"])

_RISK = "^(" + "|".join(RISK_LEVELS) + ")$"


class ToolIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(..., min_length=2, max_length=200, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$")
    kind: str = Field(
        ...,
        pattern="^(http|sandbox|function)$",
        description="MCP tools come from MCP server discovery",
    )
    description: str = Field("", max_length=2000)
    actions: list[str] = Field(default_factory=list, max_length=50)
    input_schema: dict[str, Any] = Field(default_factory=dict)
    constraints: dict[str, Any] = Field(default_factory=dict)
    resource_template: str = Field("", max_length=300)
    risk: str = Field("medium", pattern=_RISK)
    sensitive: bool = False
    external: bool = False
    config: dict[str, Any] = Field(default_factory=dict)
    project_id: uuid.UUID | None = None

    @model_validator(mode="after")
    def _check(self) -> ToolIn:
        try:
            if self.input_schema:
                check_schema(self.input_schema)
            check_constraints(self.constraints)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc
        if self.kind == "http":
            url = str(self.config.get("url", ""))
            if not url.startswith(("http://", "https://")):
                raise ValueError("An http tool needs config.url (http:// or https://)")
            if str(self.config.get("method", "POST")).upper() not in (
                "GET",
                "POST",
                "PUT",
                "PATCH",
                "DELETE",
            ):
                raise ValueError("config.method is GET, POST, PUT, PATCH or DELETE")
            for name in template_fields(url):
                if not name.isidentifier():
                    raise ValueError(f"URL placeholder {name!r} must be a parameter name")
        if self.kind == "sandbox" and str(self.config.get("language", "python")) not in (
            "python",
            "node",
            "bash",
        ):
            raise ValueError("config.language is python, node or bash")
        if self.kind == "sandbox" and self.config.get("network", "none") not in ("none", "proxy"):
            raise ValueError("config.network is none or proxy")
        return self


class ToolUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    description: str | None = Field(None, max_length=2000)
    actions: list[str] | None = None
    input_schema: dict[str, Any] | None = None
    constraints: dict[str, Any] | None = None
    resource_template: str | None = Field(None, max_length=300)
    risk: str | None = Field(None, pattern=_RISK)
    sensitive: bool | None = None
    external: bool | None = None
    config: dict[str, Any] | None = None
    status: str | None = Field(None, pattern="^(active|disabled)$")


class ToolOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    name: str
    kind: str
    description: str
    actions: list[str]
    input_schema: dict[str, Any]
    constraints: dict[str, Any]
    resource_template: str
    risk: str
    sensitive: bool
    external: bool
    config: dict[str, Any]
    status: str
    project_id: uuid.UUID | None
    mcp_server_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime
    calls_24h: int = 0
    denied_24h: int = 0
    granted_roles: list[str] = Field(default_factory=list)


class GrantIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: str = Field(..., min_length=1, max_length=64)
    actions: list[str] = Field(default_factory=list)
    resource: str = Field("*", max_length=300)
    condition: str = Field("", max_length=1000)


class ReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    approve: bool


class ServerIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    slug: str = Field(..., min_length=2, max_length=48, pattern=r"^[a-z0-9][a-z0-9-]*$")
    name: str = Field(..., min_length=1, max_length=120)
    description: str = Field("", max_length=1000)
    transport: str = Field("http", pattern="^(http|stdio)$")
    url: str | None = Field(None, max_length=2000)
    command: str | None = Field(None, max_length=500)
    args: list[str] = Field(default_factory=list, max_length=50)
    # {"Authorization": "github-token|Bearer {value}"} or {"API_KEY": "github-token"}
    secret_bindings: dict[str, str] = Field(default_factory=dict)
    default_risk: str = Field("medium", pattern=_RISK)
    project_id: uuid.UUID | None = None
    discover: bool = True


class ServerUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(None, max_length=120)
    description: str | None = Field(None, max_length=1000)
    url: str | None = Field(None, max_length=2000)
    command: str | None = Field(None, max_length=500)
    args: list[str] | None = None
    secret_bindings: dict[str, str] | None = None
    default_risk: str | None = Field(None, pattern=_RISK)
    enabled: bool | None = None


class ServerOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    slug: str
    name: str
    description: str
    transport: str
    url: str | None
    command: str | None
    args: list[str]
    secret_bindings: dict[str, Any]
    default_risk: str
    enabled: bool
    health: str
    health_detail: str | None
    latency_ms: int | None
    server_info: dict[str, Any]
    last_checked_at: datetime | None
    last_discovered_at: datetime | None
    created_at: datetime
    tools: int = 0
    pending_review: int = 0


class VersionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    tool_name: str
    fingerprint: str
    change: str
    definition: dict[str, Any]
    seen_at: datetime
    reviewed_at: datetime | None


class DiscoverOut(BaseModel):
    added: list[str]
    changed: list[str]
    removed: list[str]
    flagged: list[str]


async def _tools_out(session: SessionDep, rows: list[Tool]) -> list[ToolOut]:
    if not rows:
        return []
    since = datetime.now(UTC) - timedelta(hours=24)
    names = [t.name for t in rows]
    org_id = rows[0].org_id
    stats = {
        r[0]: (int(r[1]), int(r[2]))
        for r in (
            await session.execute(
                select(
                    Decision.tool,
                    func.count(),
                    func.count().filter(Decision.would_be.in_(("deny", "quarantine"))),
                )
                .where(Decision.org_id == org_id, Decision.at >= since, Decision.tool.in_(names))
                .group_by(Decision.tool)
            )
        ).all()
    }
    grants = (
        await session.execute(
            select(Permission.tool, AgentRole.name)
            .join(AgentRole, AgentRole.id == Permission.role_id)
            .where(Permission.org_id == org_id)
        )
    ).all()
    from agentguard.policies.engine import glob

    out = []
    for t in rows:
        item = ToolOut.model_validate(t)
        item.calls_24h, item.denied_24h = stats.get(t.name, (0, 0))
        item.granted_roles = sorted({role for pattern, role in grants if glob([pattern], t.name)})
        out.append(item)
    return out


async def _tool(session: SessionDep, org_id: uuid.UUID, tool_id: uuid.UUID) -> Tool:
    tool = await session.get(Tool, tool_id)
    if tool is None or tool.org_id != org_id:
        raise NotFoundError("Tool not found")
    return tool


@router.post(
    "/tools/register",
    response_model=ToolOut,
    status_code=201,
    summary="Register a tool agents may ask to use",
)
async def register_tool(
    body: ToolIn, actor: StaffWrite, container: ContainerDep, session: SessionDep
) -> ToolOut:
    if await session.scalar(
        select(Tool.id).where(Tool.org_id == actor.org_id, Tool.name == body.name)
    ):
        raise ConflictError(f"A tool named {body.name} exists", code="duplicate")
    tool = Tool(org_id=actor.org_id, **body.model_dump())
    session.add(tool)
    await session.flush()
    audit(session, actor, "tool.registered", "tool", tool.id, name=tool.name, kind=tool.kind)
    await bump(container, actor.org_id)
    await session.commit()
    return (await _tools_out(session, [tool]))[0]


@router.get("/tools", response_model=list[ToolOut], summary="Registered tools with their use")
async def list_tools(
    actor: StaffRead, session: SessionDep, kind: str | None = None, status: str | None = None
) -> list[ToolOut]:
    stmt = select(Tool).where(Tool.org_id == actor.org_id)
    if kind:
        if kind not in KINDS:
            raise AppError("Unknown kind", code="invalid_kind")
        stmt = stmt.where(Tool.kind == kind)
    if status:
        stmt = stmt.where(Tool.status == status)
    return await _tools_out(
        session, list((await session.scalars(stmt.order_by(Tool.name).limit(1000))).all())
    )


@router.get("/tools/{tool_id}", response_model=ToolOut, summary="One tool")
async def get_tool(tool_id: uuid.UUID, actor: StaffRead, session: SessionDep) -> ToolOut:
    return (await _tools_out(session, [await _tool(session, actor.org_id, tool_id)]))[0]


@router.patch("/tools/{tool_id}", response_model=ToolOut, summary="Change a tool")
async def update_tool(
    tool_id: uuid.UUID,
    body: ToolUpdate,
    actor: StaffWrite,
    container: ContainerDep,
    session: SessionDep,
) -> ToolOut:
    tool = await _tool(session, actor.org_id, tool_id)
    changes = body.model_dump(exclude_none=True)
    if body.input_schema is not None:
        try:
            check_schema(body.input_schema)
        except ValueError as exc:
            raise AppError(str(exc), code="invalid_schema") from exc
    if body.constraints is not None:
        try:
            check_constraints(body.constraints)
        except ValueError as exc:
            raise AppError(str(exc), code="invalid_constraints") from exc
    if tool.kind == "mcp" and body.config is not None:
        raise AppError("MCP tool configuration comes from the server", code="read_only")
    if tool.status == "pending_review" and body.status == "active":
        raise AppError("Review the upstream change instead", code="pending_review")
    for key, value in changes.items():
        setattr(tool, key, value)
    audit(session, actor, "tool.updated", "tool", tool.id, fields=sorted(changes))
    await bump(container, actor.org_id)
    await session.commit()
    return (await _tools_out(session, [tool]))[0]


@router.delete("/tools/{tool_id}", status_code=204, summary="Remove a tool from the registry")
async def delete_tool(
    tool_id: uuid.UUID, actor: StaffWrite, container: ContainerDep, session: SessionDep
) -> Response:
    tool = await _tool(session, actor.org_id, tool_id)
    if tool.kind == "mcp":
        raise AppError(
            "MCP tools follow their server; disable the tool or the server instead", code="mcp_tool"
        )
    audit(session, actor, "tool.deleted", "tool", tool.id, name=tool.name)
    await session.delete(tool)
    await bump(container, actor.org_id)
    await session.commit()
    return Response(status_code=204)


@router.post(
    "/tools/{tool_id}/permissions",
    response_model=ToolOut,
    summary="Grant a role permission to use this tool",
)
async def grant(
    tool_id: uuid.UUID,
    body: GrantIn,
    actor: StaffWrite,
    container: ContainerDep,
    session: SessionDep,
) -> ToolOut:
    from agentguard.policies import expr

    tool = await _tool(session, actor.org_id, tool_id)
    role = await session.scalar(
        select(AgentRole).where(AgentRole.org_id == actor.org_id, AgentRole.name == body.role)
    )
    if role is None:
        raise NotFoundError(f"No role named {body.role}")
    if body.condition:
        try:
            expr.parse(body.condition)
        except expr.ExprError as exc:
            raise AppError(str(exc), code="invalid_condition") from exc
    unknown = [a for a in body.actions if tool.actions and a not in tool.actions]
    if unknown:
        raise AppError(f"{tool.name} does not support {unknown}", code="unknown_action")
    session.add(
        Permission(
            org_id=actor.org_id,
            role_id=role.id,
            tool=tool.name,
            actions=body.actions,
            resource=body.resource,
            condition=body.condition,
        )
    )
    audit(
        session,
        actor,
        "permission.granted",
        "tool",
        tool.id,
        role=body.role,
        actions=body.actions,
        resource=body.resource,
    )
    await bump(container, actor.org_id)
    await session.commit()
    return (await _tools_out(session, [tool]))[0]


@router.post(
    "/tools/{tool_id}/review",
    response_model=ToolOut,
    summary="Accept or refuse a changed or new MCP tool",
)
async def review(
    tool_id: uuid.UUID,
    body: ReviewIn,
    actor: StaffWrite,
    container: ContainerDep,
    session: SessionDep,
) -> ToolOut:
    tool = await _tool(session, actor.org_id, tool_id)
    await catalog.review(container, session, actor, tool, body.approve)
    await session.commit()
    return (await _tools_out(session, [tool]))[0]


@router.get(
    "/tools/{tool_id}/versions",
    response_model=list[VersionOut],
    summary="Every definition an MCP tool has had",
)
async def tool_versions(
    tool_id: uuid.UUID, actor: StaffRead, session: SessionDep
) -> list[McpToolVersion]:
    tool = await _tool(session, actor.org_id, tool_id)
    if tool.mcp_server_id is None:
        return []
    return list(
        (
            await session.scalars(
                select(McpToolVersion)
                .where(
                    McpToolVersion.server_id == tool.mcp_server_id,
                    McpToolVersion.tool_name == tool.config.get("upstream_name"),
                )
                .order_by(McpToolVersion.seen_at.desc())
            )
        ).all()
    )


async def _servers_out(session: SessionDep, rows: list[McpServer]) -> list[ServerOut]:
    if not rows:
        return []
    counts: dict[tuple[uuid.UUID | None, str], int] = {
        (r[0], r[1]): int(r[2])
        for r in (
            await session.execute(
                select(Tool.mcp_server_id, Tool.status, func.count())
                .where(Tool.mcp_server_id.in_([s.id for s in rows]))
                .group_by(Tool.mcp_server_id, Tool.status)
            )
        ).all()
    }
    out = []
    for s in rows:
        item = ServerOut.model_validate(s)
        item.tools = sum(
            v for (sid, status), v in counts.items() if sid == s.id and status != "disabled"
        )
        item.pending_review = counts.get((s.id, "pending_review"), 0)
        out.append(item)
    return out


@router.get("/mcp/servers", response_model=list[ServerOut], summary="Registered MCP servers")
async def list_servers(actor: StaffRead, session: SessionDep) -> list[ServerOut]:
    rows = (
        await session.scalars(
            select(McpServer).where(McpServer.org_id == actor.org_id).order_by(McpServer.slug)
        )
    ).all()
    return await _servers_out(session, list(rows))


@router.post(
    "/mcp/servers",
    response_model=ServerOut,
    status_code=201,
    summary="Register an MCP server (and discover its tools)",
)
async def create_server(
    body: ServerIn, actor: StaffWrite, container: ContainerDep, session: SessionDep
) -> ServerOut:
    catalog.check_registration(container, body.transport, body.url, body.command)
    if await session.scalar(
        select(McpServer.id).where(McpServer.org_id == actor.org_id, McpServer.slug == body.slug)
    ):
        raise ConflictError(f"A server named {body.slug} exists", code="duplicate")
    server = McpServer(org_id=actor.org_id, **body.model_dump(exclude={"discover"}))
    session.add(server)
    await session.flush()
    audit(
        session,
        actor,
        "mcp.registered",
        "mcp_server",
        server.id,
        slug=server.slug,
        transport=server.transport,
    )
    await session.commit()
    if body.discover:
        try:
            await catalog.discover(container, session, server, actor)
        except (UpstreamError, AppError) as exc:
            server.health, server.health_detail = "down", getattr(exc, "message", str(exc))[:500]
        await session.commit()
    return (await _servers_out(session, [server]))[0]


@router.get("/mcp/servers/{server_id}", response_model=ServerOut, summary="One MCP server")
async def get_server(server_id: uuid.UUID, actor: StaffRead, session: SessionDep) -> ServerOut:
    return (
        await _servers_out(session, [await catalog.get_server(session, actor.org_id, server_id)])
    )[0]


@router.patch("/mcp/servers/{server_id}", response_model=ServerOut, summary="Change an MCP server")
async def update_server(
    server_id: uuid.UUID,
    body: ServerUpdate,
    actor: StaffWrite,
    container: ContainerDep,
    session: SessionDep,
) -> ServerOut:
    server = await catalog.get_server(session, actor.org_id, server_id)
    changes = body.model_dump(exclude_none=True)
    if {"url", "command", "args", "secret_bindings"} & set(changes):
        catalog.check_registration(
            container, server.transport, body.url or server.url, body.command or server.command
        )
        server.config_version += 1
        catalog.pool(container).invalidate(server.id)
    for key, value in changes.items():
        setattr(server, key, value)
    audit(session, actor, "mcp.updated", "mcp_server", server.id, fields=sorted(changes))
    await session.commit()
    return (await _servers_out(session, [server]))[0]


@router.delete(
    "/mcp/servers/{server_id}", status_code=204, summary="Remove an MCP server and its tools"
)
async def delete_server(
    server_id: uuid.UUID, actor: StaffWrite, container: ContainerDep, session: SessionDep
) -> Response:
    server = await catalog.get_server(session, actor.org_id, server_id)
    catalog.pool(container).invalidate(server.id)
    audit(session, actor, "mcp.deleted", "mcp_server", server.id, slug=server.slug)
    await session.delete(server)
    await bump(container, actor.org_id)
    await session.commit()
    return Response(status_code=204)


@router.post(
    "/mcp/servers/{server_id}/discover",
    response_model=DiscoverOut,
    summary="Discover the server's tools now",
)
async def discover(
    server_id: uuid.UUID, actor: StaffWrite, container: ContainerDep, session: SessionDep
) -> DiscoverOut:
    server = await catalog.get_server(session, actor.org_id, server_id)
    try:
        changes = await catalog.discover(container, session, server, actor)
    except UpstreamError as exc:
        raise AppError(exc.message, code="mcp_unreachable") from exc
    await session.commit()
    return DiscoverOut(**changes)


@router.post(
    "/mcp/servers/{server_id}/check",
    response_model=ServerOut,
    summary="Check the server's health now",
)
async def check(
    server_id: uuid.UUID, actor: StaffWrite, container: ContainerDep, session: SessionDep
) -> ServerOut:
    server = await catalog.get_server(session, actor.org_id, server_id)
    await catalog.check_health(container, session, server)
    await session.commit()
    return (await _servers_out(session, [server]))[0]
