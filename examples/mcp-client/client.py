"""Connect an MCP client to AgentGuard's governed gateway at /mcp.

The agent sees the registered servers' tools as <server>.<tool>; every call is decided by
policy first. Here reading notes is allowed and deleting one is denied, so the delete never
reaches the notes server.

    python client.py
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

from euron_agentguard import AsyncAgentGuard
from euron_agentguard.mcp import amcp_settings, is_error, open_session


def text(result: object) -> str:
    content = getattr(result, "content", [])
    return " ".join(getattr(c, "text", str(c)) for c in content)


async def main() -> int:
    async with AsyncAgentGuard(
        os.environ.get("AGENTGUARD_URL", "http://localhost:5130"),
        os.environ["AGENTGUARD_CLIENT_ID"],
        os.environ["AGENTGUARD_CLIENT_SECRET"],
        run_id="mcp-example",
    ) as guard:
        async with open_session(guard) as session:
            tools = [t.name for t in (await session.list_tools()).tools]
            print("tools:", ", ".join(tools))
            listed = await session.call_tool("notes.list_notes", {})
            print("notes.list_notes ->", text(listed))
            read = await session.call_tool("notes.read_note", {"name": "todo"})
            print("notes.read_note  ->", text(read))
            deleted = await session.call_tool("notes.delete_note", {"name": "todo"})
            print("notes.delete_note ->", "ERROR" if is_error(deleted) else "ok", text(deleted))

        # Settings for any other MCP client (an IDE, langchain-mcp-adapters).
        settings = await amcp_settings(guard)
        shown = {**settings.headers, "Authorization": "Bearer <agent token>"}
        print("\nother clients:", json.dumps({"url": settings.url, "headers": shown}))
    return 0 if not is_error(read) and is_error(deleted) else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
