# MCP client

Any MCP client can use AgentGuard's gateway at `/mcp` (streamable HTTP) with the agent's
token. The gateway lists the registered servers' tools as `<server>.<tool>` and decides every
call by policy; a denied call never reaches the upstream server.

```bash
pip install "./sdks/python[mcp]" uvicorn
python examples/mcp-client/notes_server.py --port 8096 &          # a small upstream MCP server
eval "$(uv run --with httpx python examples/bootstrap.py --mcp-url http://127.0.0.1:8096/mcp)"
python examples/mcp-client/client.py
```

```text
tools: notes.delete_note, notes.list_notes, notes.read_note
notes.list_notes -> ideas todo
notes.read_note  -> ship the SDKs
notes.delete_note -> ERROR Denied by AgentGuard (policy_deny): Agents never delete notes
```

The local API allows private upstream URLs in development (`ALLOW_PRIVATE_URLS=true`); in
production register MCP servers on reachable, non-private addresses. For clients other than
the Python `mcp` package, `mcp_settings(guard)` gives the URL and headers (the token in them
expires after 15 minutes by default, so refresh the settings).
