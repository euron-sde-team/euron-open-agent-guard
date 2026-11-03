# Examples

Each example runs against a local AgentGuard API (`make up`, API on `http://localhost:5130`)
and was run end to end against one before release.

| Example | Shows |
| --- | --- |
| [python-quickstart](python-quickstart/) | the five-minute path: allow, approval, deny and restrict, plus the `@guard.tool` decorator |
| [langgraph-agent](langgraph-agent/) | a LangGraph ReAct agent whose tools are allowed, denied and held by policy |
| [fastapi-protected-tool](fastapi-protected-tool/) | a FastAPI service that only acts on a valid, unused decision token |
| [node-quickstart](node-quickstart/) | the Node.js SDK: decisions, `guard(fn)`, and an Express route protected by a token |
| [mcp-client](mcp-client/) | an MCP client on the governed `/mcp` gateway |

## Credentials

Every example reads `AGENTGUARD_URL`, `AGENTGUARD_CLIENT_ID` and `AGENTGUARD_CLIENT_SECRET`
(the verifying examples also `AGENTGUARD_API_KEY`). Get them either way:

**In the dashboard.** Register the tools `refunds` (action `create`), `customers` (`export`),
`search` and `shell`, add a role that grants them, add the policy from
[bootstrap.py](bootstrap.py) (`POLICY`), then register an agent with that role. The client
secret and signing secret are shown once. Create a read-only API key under API keys for the
verifier examples.

**With the bootstrap script** (it calls the same management API):

```bash
eval "$(uv run --with httpx python examples/bootstrap.py)"
```

It signs up a fresh organisation (or signs in with `AGENTGUARD_ADMIN_EMAIL` and
`AGENTGUARD_ADMIN_PASSWORD`), registers everything above and prints the exports. Use
`--url` for another API address and `--mcp-url` to also register the notes MCP server of the
mcp-client example.
