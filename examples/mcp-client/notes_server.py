"""A tiny upstream MCP server (streamable HTTP) for the example: three note tools.

    python notes_server.py --port 8096        # serves http://127.0.0.1:8096/mcp

In a real deployment this is any MCP server your agents should reach only through AgentGuard.
"""

from __future__ import annotations

import argparse

from typing import Any

import uvicorn

try:  # mcp 2.x
    from mcp.server.mcpserver import MCPServer

    server: Any = MCPServer("notes")
    APP_OPTIONS: dict[str, Any] = {"stateless_http": True, "json_response": True}
except ImportError:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP

    server = FastMCP("notes", stateless_http=True, json_response=True)
    APP_OPTIONS = {}

NOTES = {"todo": "ship the SDKs", "ideas": "a guard for every agent"}


@server.tool()
def list_notes() -> list[str]:
    """The names of all notes."""
    return sorted(NOTES)


@server.tool()
def read_note(name: str) -> str:
    """Read one note."""
    return NOTES.get(name, "no such note")


@server.tool()
def delete_note(name: str) -> str:
    """Delete one note."""
    NOTES.pop(name, None)
    return f"deleted {name}"


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8096)
    args = parser.parse_args()
    app = server.streamable_http_app(**APP_OPTIONS)
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")
