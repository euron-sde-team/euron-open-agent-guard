"""MCP: connect any MCP client to AgentGuard's governed gateway at ``/mcp``.

The gateway speaks streamable HTTP. It lists the tools of every MCP server registered in
AgentGuard that this agent could use (named ``<server>.<tool>``) and runs every
``tools/call`` through the full decision pipeline: policies, approvals, limits, taint,
output scanning and audit. A call that needs approval comes back as a tool error naming
the approval; call it again with the same arguments once a person approved it.

Two ways in:

* :func:`open_session` (needs the ``mcp`` extra, 1.x or 2.x) opens an
  ``mcp.ClientSession`` whose token is refreshed automatically;
* :func:`mcp_settings` returns the URL and headers for any other client (LangChain's
  ``langchain-mcp-adapters``, an IDE's ``mcp.json``). The token in those headers expires
  after ``expires_in`` seconds (15 minutes by default), so clients that cannot refresh it
  must be given new settings.
"""

from __future__ import annotations

import asyncio
import importlib
from collections.abc import AsyncGenerator, AsyncIterator, Awaitable, Callable
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from euron_agentguard._core import RUN_HEADER, check_run_id
from euron_agentguard.aio import AsyncAgentGuard
from euron_agentguard.client import AgentGuard

if TYPE_CHECKING:
    from mcp import ClientSession


@dataclass(frozen=True)
class MCPSettings:
    """Where and how an MCP client reaches the gateway."""

    url: str
    headers: dict[str, str]

    def as_langchain(self) -> dict[str, Any]:
        """A connection for ``langchain_mcp_adapters.client.MultiServerMCPClient``."""
        return {"transport": "streamable_http", "url": self.url, "headers": dict(self.headers)}

    def as_client_config(self, name: str = "agentguard") -> dict[str, Any]:
        """An ``mcpServers`` entry in the JSON format most MCP clients read."""
        entry = {"type": "http", "url": self.url, "headers": dict(self.headers)}
        return {"mcpServers": {name: entry}}


def gateway_url(guard: AgentGuard | AsyncAgentGuard) -> str:
    return f"{guard.base_url}/mcp"


def _headers(token: str | None, run_id: str | None) -> dict[str, str]:
    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if run_id:
        headers[RUN_HEADER] = run_id
    return headers


def mcp_settings(guard: AgentGuard, *, run_id: str | None = None) -> MCPSettings:
    """Gateway settings with a current agent token (exchanged now if needed)."""
    run = check_run_id(run_id or guard.run_id)
    return MCPSettings(gateway_url(guard), _headers(guard.access_token(), run))


async def amcp_settings(guard: AsyncAgentGuard, *, run_id: str | None = None) -> MCPSettings:
    """``mcp_settings`` for ``AsyncAgentGuard``."""
    run = check_run_id(run_id or guard.run_id)
    return MCPSettings(gateway_url(guard), _headers(await guard.access_token(), run))


def is_error(result: Any) -> bool:
    """Whether an MCP tool result is an error (``is_error`` in mcp 2.x, ``isError`` in 1.x)."""
    return bool(getattr(result, "is_error", getattr(result, "isError", False)))


def _token_source(guard: AgentGuard | AsyncAgentGuard) -> Callable[..., Awaitable[str]]:
    if isinstance(guard, AsyncAgentGuard):
        return guard.access_token

    async def token(*, force: bool = False) -> str:
        return await asyncio.to_thread(guard.access_token, force=force)

    return token


def _auth_for(http_lib: Any, token: Callable[..., Awaitable[str]]) -> Any:
    """An ``Auth`` of the HTTP library the installed mcp uses (httpx in 1.x, httpx2 in 2.x)
    that sends a fresh agent token and retries once with a new one on 401."""

    class _Auth(http_lib.Auth):  # type: ignore[misc]
        async def async_auth_flow(self, request: Any) -> AsyncGenerator[Any, Any]:
            request.headers["Authorization"] = f"Bearer {await token()}"
            response = yield request
            if response.status_code == 401:
                request.headers["Authorization"] = f"Bearer {await token(force=True)}"
                yield request

    return _Auth()


@asynccontextmanager
async def open_session(
    guard: AgentGuard | AsyncAgentGuard, *, run_id: str | None = None
) -> AsyncIterator[ClientSession]:
    """An initialised MCP ``ClientSession`` on the gateway, authenticated as the agent.

    Works with the ``mcp`` package 1.x and 2.x; the token is refreshed automatically.
    ::

        async with open_session(guard) as session:
            tools = await session.list_tools()
            result = await session.call_tool("files.read", {"path": "notes.txt"})
            if is_error(result): ...
    """
    from mcp import ClientSession

    transport: Any = importlib.import_module("mcp.client.streamable_http")
    run = check_run_id(run_id or guard.run_id)
    url = gateway_url(guard)
    headers = _headers(None, run)
    # mcp 2.x talks httpx2, mcp 1.x httpx; recent 1.x and 2.x take a ready http client.
    http_lib = getattr(transport, "httpx2", None) or transport.httpx
    auth = _auth_for(http_lib, _token_source(guard))
    async with AsyncExitStack() as stack:
        if hasattr(transport, "streamable_http_client"):
            client = await stack.enter_async_context(
                transport.create_mcp_http_client(headers=headers, auth=auth)
            )
            streams = await stack.enter_async_context(
                transport.streamable_http_client(url, http_client=client)
            )
        else:  # older 1.x
            streams = await stack.enter_async_context(
                transport.streamablehttp_client(url, headers=headers, auth=auth)
            )
        read, write = streams[0], streams[1]
        session = await stack.enter_async_context(ClientSession(read, write))
        await session.initialize()
        yield session


__all__ = [
    "MCPSettings",
    "amcp_settings",
    "gateway_url",
    "is_error",
    "mcp_settings",
    "open_session",
]
