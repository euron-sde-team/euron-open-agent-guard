# euron-agentguard (Python)

The Python SDK for [Euron Open AgentGuard](../../README.md), the self-hosted security gateway
for AI agents. It is part of the open-source initiative of **ENGAGESPHERE TECHNOLOGY PRIVATE
LIMITED** and is MIT licensed.

```bash
pip install euron-agentguard              # core: httpx and PyJWT only
pip install "euron-agentguard[langgraph]" # LangChain and LangGraph tools
pip install "euron-agentguard[crewai]"    # CrewAI tools (Python 3.11 or newer)
pip install "euron-agentguard[fastapi]"   # protect your own FastAPI tool
pip install "euron-agentguard[mcp]"       # MCP client sessions on the /mcp gateway
```

The package is not on PyPI yet (publishing is on the roadmap). Until then install it from
this repository: `pip install ./sdks/python` or `uv pip install -e "./sdks/python[langgraph]"`.

```python
from euron_agentguard import AgentGuard

guard = AgentGuard("http://localhost:5130", client_id, client_secret)

decision = guard.authorize("refunds", "create", parameters={"amount": 50, "customer": "c-1"})
if decision.allowed:
    refund(50, "c-1")
elif decision.needs_approval:
    status = decision.wait_for_approval(timeout=300)   # a person decides in the dashboard
```

| What | Where |
| --- | --- |
| `AgentGuard`, `AsyncAgentGuard` | authorize, execute, scan, ask a person, approvals, runs, `@guard.tool` |
| `DecisionVerifier`, `AsyncDecisionVerifier` | verify and redeem a decision token on the tool side |
| `euron_agentguard.fastapi.require_decision` | a FastAPI dependency that does the verification |
| `euron_agentguard.langgraph.guard_tools` | wrap LangChain tools for `create_react_agent` or `ToolNode` |
| `euron_agentguard.crewai.guard_crew_tool` | wrap a CrewAI `BaseTool` |
| `euron_agentguard.mcp.open_session` | an MCP `ClientSession` on the governed gateway |
| `action_hash`, `canonical_json` | the action hash, byte for byte the same as the API |

Every failure to decide is a denial: `authorize` returns `decision="deny"` with
`reason_code="guard_unavailable"` when AgentGuard cannot be reached. The full guide is
[docs/guides/sdk-python.md](../../docs/guides/sdk-python.md); framework integrations are in
[docs/guides/frameworks.md](../../docs/guides/frameworks.md).

## Development

```bash
uv sync                                    # Python 3.12 dev environment, all extras
uv run pytest tests/unit                   # mocked HTTP, no network
AGENTGUARD_URL=http://localhost:5130 uv run pytest tests/integration   # a real API
uv run ruff check src tests && uv run ruff format --check src tests && uv run mypy src tests
uv build                                   # wheel and sdist into dist/
```

The integration suite signs up its own organisation on the API it is pointed at, so it never
touches existing data. The API must run with `PUBLIC_API_URL` equal to `AGENTGUARD_URL`,
because decision tokens carry it as their issuer.
