"""The MCP server catalog: registration, discovery, change review and health.

Discovery lists every tool a server advertises and fingerprints each definition (name,
description, schemas, annotations). Tools become entries in the tool registry, named
``<server>.<tool>``, so permissions, policies, limits and audit treat them like any other
tool.

Tool definitions are themselves untrusted: a description can carry instructions for the
model ("tool poisoning"). So:

* on the first discovery tools are added as ``active`` unless their description fails the
  injection scan;
* afterwards, a **new** tool, a **changed** definition (a "rug pull") or a description that
  fails the scan puts the tool in ``pending_review``: every call is denied until a person
  reviews the change, and a threat is raised;
* a removed tool is disabled.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from typing import Any

import orjson
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agentguard.audit.service import Actor, audit, system_actor
from agentguard.core.container import Container
from agentguard.core.errors import AppError, NotFoundError
from agentguard.core.net import check_url, host_of
from agentguard.mcp.models import McpServer, McpToolVersion
from agentguard.mcp.upstream import UpstreamError, UpstreamPool, UpstreamSpec, probe
from agentguard.protection import injection
from agentguard.tools.models import Tool

DOWN_AFTER = 3


def _now() -> datetime:
    return datetime.now(UTC)


def fingerprint(definition: dict[str, Any]) -> str:
    return hashlib.sha256(
        orjson.dumps(definition, option=orjson.OPT_SORT_KEYS, default=str)
    ).hexdigest()


def pool(container: Container) -> UpstreamPool:
    existing = container.extras.get("mcp_pool")
    if existing is None:
        existing = UpstreamPool()
        container.extras["mcp_pool"] = existing
    assert isinstance(existing, UpstreamPool)
    return existing


def check_registration(
    container: Container, transport: str, url: str | None, command: str | None
) -> None:
    if transport == "http":
        if not url:
            raise AppError("An HTTP server needs a URL", code="url_required")
        try:
            check_url(url, "URL")
        except ValueError as exc:
            raise AppError(str(exc), code="invalid_url") from exc
    elif transport == "stdio":
        if not command:
            raise AppError("A stdio server needs a command", code="command_required")
        # Registering a stdio server runs a command on this host: only allowlisted ones.
        if command not in container.settings.stdio_allowed_commands:
            raise AppError(
                "This command is not on the operator's STDIO_ALLOWED_COMMANDS list",
                code="command_not_allowed",
            )
    else:
        raise AppError("Transport is http or stdio", code="invalid_transport")


async def spec_for(
    container: Container, session: AsyncSession, server: McpServer, *, purpose: str = "mcp_upstream"
) -> UpstreamSpec:
    """The connection settings with secrets decrypted (in memory, for one connection)."""
    from agentguard.network import service as network
    from agentguard.secrets import service as secrets

    host = host_of(server.url) if server.url else None
    if server.transport == "http" and server.url:
        import httpx

        parsed = httpx.URL(server.url)
        verdict, _ = await network.decide(
            session,
            server.org_id,
            None,
            host=host or "",
            port=parsed.port or (443 if parsed.scheme == "https" else 80),
            allow_private=container.settings.allow_private_urls,
        )
        if not verdict.allowed:
            raise UpstreamError(
                f"The organisation's network policy does not allow {host} ({verdict.reason})"
            )
    values: dict[str, str] = {}
    for target, binding in (server.secret_bindings or {}).items():
        name, _, template = str(binding).partition("|")
        resolved = await secrets.resolve_for_use(
            container,
            session,
            server.org_id,
            name,
            purpose=purpose,
            agent_id=None,
            decision_id=None,
            host=host,
        )
        values[str(target)] = (
            template.replace("{value}", resolved.value) if template else resolved.value
        )
    return UpstreamSpec(
        server_id=server.id,
        slug=server.slug,
        transport=server.transport,
        config_version=server.config_version,
        url=server.url,
        command=server.command,
        args=tuple(server.args),
        headers=values if server.transport == "http" else {},
        env=values if server.transport == "stdio" else {},
    )


def _definition(tool: Any) -> dict[str, Any]:
    return {
        "name": tool.name,
        "title": getattr(tool, "title", None),
        "description": tool.description or "",
        "input_schema": tool.input_schema or {},
        "output_schema": getattr(tool, "output_schema", None),
        "annotations": tool.annotations.model_dump(mode="json", exclude_none=True)
        if tool.annotations
        else {},
    }


async def discover(
    container: Container, session: AsyncSession, server: McpServer, actor: Actor | None = None
) -> dict[str, list[str]]:
    """List the server's tools and reconcile the registry. Returns what changed."""
    from agentguard.threats import service as threats

    actor = actor or system_actor(server.org_id, "mcp-discovery")
    spec = await spec_for(container, session, server, purpose="mcp_discovery")
    result = await probe(spec, connect_timeout_s=10.0, timeout_s=30.0, full=True)
    first = server.last_discovered_at is None
    existing = {
        t.name: t
        for t in (await session.scalars(select(Tool).where(Tool.mcp_server_id == server.id))).all()
    }
    seen: set[str] = set()
    changes: dict[str, list[str]] = {"added": [], "changed": [], "removed": [], "flagged": []}
    for upstream_tool in result.tools:
        definition = _definition(upstream_tool)
        full_name = f"{server.slug}.{upstream_tool.name}"
        seen.add(full_name)
        fp = fingerprint(definition)
        scan = injection.scan(f"{definition['title'] or ''}\n{definition['description']}")
        poisoned = scan.verdict == "injection"
        tool = existing.get(full_name)
        if tool is None:
            status = "pending_review" if (poisoned or not first) else "active"
            tool = Tool(
                org_id=server.org_id,
                project_id=server.project_id,
                name=full_name,
                kind="mcp",
                description=definition["description"][:2000],
                actions=["call"],
                input_schema=definition["input_schema"],
                risk=server.default_risk,
                sensitive=server.default_risk in ("high", "critical"),
                external=False,
                config={
                    "server_id": str(server.id),
                    "upstream_name": upstream_tool.name,
                    "fingerprint": fp,
                },
                status=status,
                mcp_server_id=server.id,
            )
            session.add(tool)
            session.add(
                McpToolVersion(
                    org_id=server.org_id,
                    server_id=server.id,
                    tool_name=upstream_tool.name,
                    fingerprint=fp,
                    definition=definition,
                    change="added",
                )
            )
            changes["added"].append(full_name)
        elif tool.config.get("fingerprint") != fp:
            tool.config = {**tool.config, "fingerprint": fp}
            tool.description = definition["description"][:2000]
            tool.input_schema = definition["input_schema"]
            tool.status = "pending_review"
            session.add(
                McpToolVersion(
                    org_id=server.org_id,
                    server_id=server.id,
                    tool_name=upstream_tool.name,
                    fingerprint=fp,
                    definition=definition,
                    change="changed",
                )
            )
            changes["changed"].append(full_name)
        elif tool.status == "disabled" and tool.config.get("removed"):
            tool.status = "pending_review"
            tool.config = {k: v for k, v in tool.config.items() if k != "removed"}
            changes["added"].append(full_name)
        if poisoned and tool.status != "disabled":
            tool.status = "pending_review"
            changes["flagged"].append(full_name)
            await threats.record(
                session,
                server.org_id,
                kind="malicious_tool_output",
                severity="high",
                rule="tool_description_injection",
                summary=f"The description of {full_name} contains instructions for the model",
                details=scan.as_dict(),
                dedupe=full_name,
                respond=False,
            )
    for name, tool in existing.items():
        if name not in seen and tool.status != "disabled":
            tool.status = "disabled"
            tool.config = {**tool.config, "removed": True}
            session.add(
                McpToolVersion(
                    org_id=server.org_id,
                    server_id=server.id,
                    tool_name=name.split(".", 1)[1],
                    fingerprint="",
                    definition={},
                    change="removed",
                )
            )
            changes["removed"].append(name)
    if not first and (changes["added"] or changes["changed"]):
        from agentguard.integrations.service import dispatch

        await threats.record(
            session,
            server.org_id,
            kind="tool_definition_changed",
            severity="medium",
            rule="mcp_rug_pull",
            summary=f"{server.slug} changed {len(changes['changed'])} and added {len(changes['added'])} tool(s); held for review",
            details=changes,
            dedupe=server.slug,
            respond=False,
        )
        await dispatch(session, server.org_id, "tool.changed", {"server": server.slug, **changes})
    server.server_info = result.server_info
    server.last_discovered_at = _now()
    server.health, server.health_detail, server.consecutive_failures = "up", None, 0
    server.latency_ms = result.latency_ms
    audit(
        session,
        actor,
        "mcp.discovered",
        "mcp_server",
        server.id,
        **{k: len(v) for k, v in changes.items()},
    )
    from agentguard.policies.service import bump

    await bump(container, server.org_id)
    return changes


async def check_health(container: Container, session: AsyncSession, server: McpServer) -> str:
    try:
        spec = await spec_for(container, session, server, purpose="mcp_health")
        result = await probe(spec, connect_timeout_s=5.0, timeout_s=10.0, full=False)
    except (UpstreamError, AppError) as exc:
        server.consecutive_failures += 1
        server.health = "down" if server.consecutive_failures >= DOWN_AFTER else "degraded"
        server.health_detail = getattr(exc, "message", str(exc))[:500]
    else:
        server.consecutive_failures = 0
        server.health = "up" if result.latency_ms < 2000 else "degraded"
        server.health_detail = None
        server.latency_ms = result.latency_ms
    server.last_checked_at = _now()
    return server.health


async def review(
    container: Container, session: AsyncSession, actor: Actor, tool: Tool, approve: bool
) -> Tool:
    """Accept a changed or new MCP tool (active) or keep it out (disabled)."""
    if tool.status != "pending_review":
        raise AppError("This tool has no change waiting for review", code="not_pending")
    tool.status = "active" if approve else "disabled"
    if tool.mcp_server_id is not None:
        rows = (
            await session.scalars(
                select(McpToolVersion).where(
                    McpToolVersion.server_id == tool.mcp_server_id,
                    McpToolVersion.tool_name == tool.config.get("upstream_name"),
                    McpToolVersion.reviewed_at.is_(None),
                )
            )
        ).all()
        for row in rows:
            row.reviewed_at = _now()
            row.reviewed_by = actor.id if actor.kind == "user" else None
    audit(session, actor, "tool.reviewed", "tool", tool.id, approved=approve)
    from agentguard.policies.service import bump

    await bump(container, tool.org_id)
    return tool


async def get_server(session: AsyncSession, org_id: uuid.UUID, server_id: uuid.UUID) -> McpServer:
    server = await session.get(McpServer, server_id)
    if server is None or server.org_id != org_id:
        raise NotFoundError("MCP server not found")
    return server


async def call_tool(
    container: Container,
    session: AsyncSession,
    tool: Tool,
    arguments: dict[str, Any],
    *,
    agent_id: uuid.UUID,
    decision_id: uuid.UUID,
) -> dict[str, Any]:
    """Call an MCP tool through the pool. Returns the CallToolResult as JSON."""
    server = await session.get(McpServer, tool.mcp_server_id) if tool.mcp_server_id else None
    if server is None or not server.enabled:
        raise AppError("The MCP server of this tool is not available", code="server_unavailable")

    async def load() -> UpstreamSpec:
        return await spec_for(container, session, server)

    try:
        result = await pool(container).call_tool(
            server.id,
            server.config_version,
            load,
            str(tool.config.get("upstream_name")),
            arguments,
            float(tool.config.get("timeout_s", 60.0)),
        )
    except UpstreamError as exc:
        from agentguard.decisions.execute import ExecutionError

        raise ExecutionError(exc.message, code="mcp_upstream_error") from exc
    out: dict[str, Any] = result.model_dump(mode="json", by_alias=True, exclude_none=True)
    return out
