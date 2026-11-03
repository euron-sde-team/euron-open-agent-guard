"""The governed MCP endpoint: ``/mcp`` (streamable HTTP, stateless, JSON responses).

An agent configures one URL and its AgentGuard token. It sees the tools of every registered
MCP server it could use, named ``<server>.<tool>``; tools it can never use are absent from
``tools/list`` and refused on ``tools/call`` like tools that do not exist.

Every ``tools/call`` goes through the full decision pipeline (source ``mcp``) and, when
allowed, through trusted execution, so MCP calls get the same policies, approvals, limits,
taint, output scanning and audit as any other action. A call that needs approval returns
a tool error naming the approval; the agent retries the same call once a reviewer approved
it (the approval is bound to the exact arguments).

The run is taken from the ``X-AgentGuard-Run`` header when the client sends one.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

import mcp_types as types
import orjson
from mcp import MCPError
from mcp.server import Server
from mcp.server.context import ServerRequestContext
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from mcp_types import INTERNAL_ERROR
from sqlalchemy import select
from starlette.datastructures import Headers
from starlette.types import Receive, Scope, Send

from agentguard import __version__
from agentguard.core.container import Container
from agentguard.core.errors import AuthenticationError

log = logging.getLogger("agentguard.mcp")
STATE_KEY = "agentguard_mcp"
INSTRUCTIONS = (
    "Tools from the MCP servers registered in AgentGuard, named <server>.<tool>. Every call is "
    "checked against your organisation's policies. A result that says an approval is needed "
    "names the approval: retry the same call with the same arguments after it is approved."
)
_RUN = re.compile(r"^[A-Za-z0-9_.:@/-]{1,128}$")


@dataclass(frozen=True, slots=True)
class Caller:
    token: str
    run_id: str | None
    ip: str | None


def _caller(ctx: ServerRequestContext[Any, Any]) -> Caller:
    caller = getattr(getattr(ctx.request, "state", None), STATE_KEY, None)
    if not isinstance(caller, Caller):
        raise MCPError(code=INTERNAL_ERROR, message="The request was not authenticated.")
    return caller


def _text(value: Any) -> str:
    return (
        value
        if isinstance(value, str)
        else orjson.dumps(value, default=str, option=orjson.OPT_INDENT_2).decode()
    )


def build_server(container: Container) -> Server[Any]:
    from agentguard.access.resolve import for_agent
    from agentguard.decisions import service as decisions
    from agentguard.decisions.schemas import AuthorizeRequest
    from agentguard.identity import service as identity
    from agentguard.org.models import Project
    from agentguard.policies import engine
    from agentguard.policies.service import active_policies
    from agentguard.tools.models import Tool

    async def list_tools(
        ctx: ServerRequestContext[Any, Any], params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        caller = _caller(ctx)
        async with container.db.sessionmaker() as session:
            principal = await identity.authenticate(container, session, caller.token)
            agent = principal.agent
            project = await session.get(Project, agent.project_id)
            granted = await for_agent(container, session, agent.org_id, agent.project_id, agent.id)
            policies = await active_policies(container, session, agent.org_id)
            from agentguard.org.models import Org

            org_slug = await session.scalar(select(Org.slug).where(Org.id == agent.org_id))
            data = {
                "org": {"slug": org_slug},
                "agent": {
                    "slug": agent.slug,
                    "project": project.slug if project else "",
                    "roles": granted.roles,
                    "labels": dict(agent.labels),
                    "framework": agent.framework,
                },
                "project": {"environment": project.environment if project else ""},
            }
            rows = (
                await session.scalars(
                    select(Tool)
                    .where(Tool.org_id == agent.org_id, Tool.kind == "mcp", Tool.status == "active")
                    .order_by(Tool.name)
                )
            ).all()
            await session.commit()
        tools = [
            types.Tool(
                name=t.name,
                description=t.description or None,
                input_schema=t.input_schema or {"type": "object"},
            )
            for t in rows
            if agent.status == "active"
            and engine.could_allow(policies, granted.grants, data, t.name)
        ]
        return types.ListToolsResult(tools=tools)

    async def call_tool(
        ctx: ServerRequestContext[Any, Any], params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        caller = _caller(ctx)
        try:
            async with container.db.sessionmaker() as session:
                principal = await identity.authenticate(container, session, caller.token)
                request = AuthorizeRequest(
                    tool=params.name,
                    action="call",
                    parameters=dict(params.arguments or {}),
                    run_id=caller.run_id,
                )
                out = await decisions.execute(
                    container, session, principal, request, ip=caller.ip, source="mcp"
                )
        except AuthenticationError as exc:
            return types.CallToolResult(
                content=[types.TextContent(text=exc.message)], is_error=True
            )
        except Exception as exc:
            log.exception("mcp call failed")
            raise MCPError(
                code=INTERNAL_ERROR, message="AgentGuard failed to run the call."
            ) from exc
        if out.would_be == "require_approval" and out.approval is not None:
            return types.CallToolResult(
                content=[
                    types.TextContent(
                        text=(
                            f"Held for approval ({out.reason}). Approval {out.approval.id} expires {out.approval.expires_at.isoformat()}. "
                            "Retry this exact call after a reviewer approves it."
                        )
                    )
                ],
                is_error=True,
            )
        if not out.allowed:
            if out.reason_code == "unknown_tool":
                raise MCPError(code=-32602, message=f"Unknown tool: {params.name}")
            return types.CallToolResult(
                content=[
                    types.TextContent(
                        text=f"Denied by AgentGuard ({out.reason_code}): {out.reason}"
                    )
                ],
                is_error=True,
            )
        if not out.executed:
            message = out.result_meta.get("message") or "The tool could not be run."
            return types.CallToolResult(
                content=[types.TextContent(text=str(message))], is_error=True
            )
        result = out.result
        if isinstance(result, dict) and "content" in result:
            try:
                return types.CallToolResult.model_validate(result)
            except ValueError:
                log.info("upstream result is not a CallToolResult; relaying it as text")
        return types.CallToolResult(content=[types.TextContent(text=_text(result))], is_error=False)

    return Server(
        "agentguard",
        version=__version__,
        title="Euron Open AgentGuard",
        description="Every MCP tool your organisation registered, governed by AgentGuard.",
        instructions=INSTRUCTIONS,
        on_list_tools=list_tools,
        on_call_tool=call_tool,
    )


def build_manager(container: Container) -> StreamableHTTPSessionManager:
    return StreamableHTTPSessionManager(
        app=build_server(container),
        json_response=True,
        stateless=True,
        # Every request carries the agent's token, so DNS rebinding (which relies on an
        # ambient credential) gains nothing.
        security_settings=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )


async def _refuse(send: Send, status: int, message: str) -> None:
    body = orjson.dumps(
        {"jsonrpc": "2.0", "id": None, "error": {"code": -32001, "message": message}}
    )
    headers = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]
    if status == 401:
        headers.append((b"www-authenticate", b'Bearer realm="agentguard", error="invalid_token"'))
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


class GatewayEndpoint:
    """ASGI app mounted at /mcp. Checks the bearer token is present, then hands over."""

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        app = scope["app"]
        manager: StreamableHTTPSessionManager = app.state.mcp_manager
        headers = Headers(scope=scope)
        authorization = headers.get("authorization", "")
        if not authorization.lower().startswith("bearer ") or not authorization[7:].strip():
            await _refuse(
                send, 401, "Send the agent's AgentGuard token: Authorization: Bearer <token>"
            )
            return
        container: Container = app.state.container
        from agentguard.identity import service as identity

        try:
            async with container.db.sessionmaker() as session:
                principal = await identity.authenticate(
                    container, session, authorization[7:].strip()
                )
                await session.commit()
            if principal.agent.require_signed_requests:
                # MCP clients cannot sign requests; an agent that must sign uses the REST API.
                await _refuse(send, 403, "This agent must sign its requests; use the REST API")
                return
        except AuthenticationError as exc:
            await _refuse(send, 401, exc.message)
            return
        run = headers.get("x-agentguard-run")
        client = scope.get("client")
        scope.setdefault("state", {})[STATE_KEY] = Caller(
            token=authorization[7:].strip(),
            run_id=run if run and _RUN.match(run) else None,
            ip=client[0] if client else None,
        )
        await manager.handle_request(scope, receive, send)
