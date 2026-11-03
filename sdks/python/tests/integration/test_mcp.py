"""The MCP gateway through the SDK helper: a real upstream MCP server registered in
AgentGuard, a real MCP client session on ``/mcp``, governed by policy."""

from __future__ import annotations

import secrets
import socket
import threading
import time
from collections.abc import Iterator
from typing import Any

import pytest
import uvicorn

from euron_agentguard import AgentGuard, AsyncAgentGuard
from euron_agentguard.mcp import is_error, mcp_settings, open_session

from .conftest import URL, Admin

CALLS: list[str] = []


def _upstream() -> tuple[Any, dict[str, Any]]:
    """The upstream server, on mcp 2.x (MCPServer) or 1.x (FastMCP)."""
    try:
        from mcp.server.mcpserver import MCPServer  # type: ignore[import-not-found, unused-ignore]

        server: Any = MCPServer("notes")
        options: dict[str, Any] = {"stateless_http": True, "json_response": True}
    except ImportError:
        from mcp.server.fastmcp import FastMCP

        server = FastMCP("notes", stateless_http=True, json_response=True)
        options = {}

    @server.tool()  # type: ignore[untyped-decorator, unused-ignore]
    def read_note(name: str) -> str:
        """Read a note by name."""
        CALLS.append(f"read:{name}")
        return f"contents of {name}"

    @server.tool()  # type: ignore[untyped-decorator, unused-ignore]
    def delete_note(name: str) -> str:
        """Delete a note by name."""
        CALLS.append(f"delete:{name}")
        return "deleted"

    return server, options


@pytest.fixture(scope="module")
def upstream_url() -> Iterator[str]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    mcp_server, options = _upstream()
    app = mcp_server.streamable_http_app(**options)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}/mcp"
    server.should_exit = True
    thread.join(5)


async def test_mcp_gateway_governs_calls(admin: Admin, upstream_url: str) -> None:
    slug = f"notes{secrets.token_hex(2)}"
    server = admin.call(
        "POST",
        "/api/v1/mcp/servers",
        {"slug": slug, "name": "Notes", "url": upstream_url, "default_risk": "low"},
    )
    assert server["tools"] == 2, server
    admin.role(f"notes-{slug}", [{"tool": f"{slug}.*", "actions": ["*"]}])
    admin.policy(
        f"name: no-delete-{slug}\nrules:\n  - tools: [{slug}.delete_note]\n"
        "    decision: deny\n    reason: Notes are never deleted by agents\n"
    )
    c = admin.agent(f"mcp-{secrets.token_hex(3)}", [f"notes-{slug}"], framework="mcp")
    CALLS.clear()
    async with (
        AsyncAgentGuard(URL, c.client_id, c.client_secret, run_id="mcp-run-1") as guard,
        open_session(guard) as session,
    ):
        names = {t.name for t in (await session.list_tools()).tools}
        assert names == {f"{slug}.read_note", f"{slug}.delete_note"}
        ok = await session.call_tool(f"{slug}.read_note", {"name": "todo"})
        assert not is_error(ok)
        assert "contents of todo" in str(ok.content[0])
        denied = await session.call_tool(f"{slug}.delete_note", {"name": "todo"})
        assert is_error(denied)
        assert "never deleted" in str(denied.content[0])
    assert CALLS == ["read:todo"]  # the denied call never reached the upstream server

    with AgentGuard(URL, c.client_id, c.client_secret) as sync_guard:
        settings = mcp_settings(sync_guard, run_id="r1")
    assert settings.url == f"{URL}/mcp"
    assert settings.headers["Authorization"].startswith("Bearer ey")
    assert settings.headers["X-AgentGuard-Run"] == "r1"
    assert settings.as_langchain()["transport"] == "streamable_http"
