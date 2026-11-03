# Framework integrations

AgentGuard needs one thing from a framework: a place to ask before a tool runs. Each
integration below puts the `authorize` call there, keeps the tool's name, description and
argument schema unchanged (the model sees the same tool), and turns a refusal into something
the agent can read instead of a crash. They are optional extras of the
[Python SDK](sdk-python.md), so the core package stays small.

| Framework | Integration | Extra | Tested against |
| --- | --- | --- | --- |
| LangChain, LangGraph | `euron_agentguard.langgraph.guard_tools` | `[langgraph]` | langgraph 1.2, langchain-core 1.7, a real `create_react_agent` and `ToolNode` |
| CrewAI | `euron_agentguard.crewai.guard_crew_tool` | `[crewai]` | crewai 1.15 (`BaseTool.run`, `to_structured_tool`) |
| MCP clients | `euron_agentguard.mcp.open_session`, `mcp_settings` | `[mcp]` | mcp 1.20, 1.25, 1.30 and 2.3 against the real `/mcp` gateway |
| FastAPI (tool side) | `euron_agentguard.fastapi.require_decision` | `[fastapi]` | FastAPI 0.162 |
| Express (tool side) | `@euron/agentguard/express` | Node.js SDK | Express 5.3 |
| AutoGen, anything else | the `@guard.tool` decorator | none | not covered by the test suite (see below) |

An integration is a client-side check: it stops an honest agent from doing what policy
forbids, but code that controls the agent process could call the tool without it. For tools
that must be protected even then, use `execute` (AgentGuard runs the tool) or have the tool
verify a decision token. See [Why a client-side check is not enough](sdk-python.md#why-a-client-side-check-is-not-enough).

## LangChain and LangGraph

```python
from langgraph.prebuilt import create_react_agent        # or langchain.agents.create_agent
from euron_agentguard import AgentGuard
from euron_agentguard.langgraph import guard_tools

guard = AgentGuard(AGENTGUARD_URL, CLIENT_ID, CLIENT_SECRET)
tools = guard_tools(guard, [search, refund, shell], actions={"refund": "create"})
agent = create_react_agent(model, tools)
agent.invoke({"messages": [("user", "...")]}, config={"configurable": {"thread_id": "t-1"}})
```

Each wrapped tool is a `BaseTool` (`GuardedTool`) that, on every call, authorizes with the
tool's arguments as parameters:

- **allowed**: the original tool runs; inside it `current_decision()` returns the decision;
- **denied**: the tool does not run; the tool message says `AgentGuard denied this action
  (<reason_code>): <reason>. It has not run. Do not retry it with the same arguments.`;
- **approval required**: the tool does not run; the message names the approval and its URL
  and tells the model to call the tool again with the same arguments once approved. With
  `wait=True` the call blocks until a person decides, then asks again and runs only if
  AgentGuard now allows it;
- **AgentGuard unreachable**: denied (fail closed), with a message saying so.

Options: `names={"refund": "payments.refund"}` maps a LangChain tool name to its AgentGuard
tool name, `actions` maps it to an action (default `call`), `execute=True` has AgentGuard run
the tool itself (for http, MCP and sandbox tools; the local function is not called and the
agent holds no credentials), `raise_on_deny=True` raises `ActionDenied` instead of returning a
message (`ToolNode` error handling then applies). The LangGraph thread id becomes the run id
when the guard sets none, so run limits and taint follow the conversation. Both `invoke` and
`ainvoke` work; with `AsyncAgentGuard` use the async path. Tools with
`response_format="content_and_artifact"` keep their artifact. Tools with injected arguments
(`InjectedState`, `InjectedToolCallId`) are not supported in 0.1.0.

## CrewAI

```python
from crewai import Agent
from euron_agentguard.crewai import guard_crew_tool

refund = guard_crew_tool(guard, RefundTool(), name="refunds", action="create")
agent = Agent(role="Support", goal="...", backstory="...", tools=[refund])
```

`GuardedCrewTool` is a CrewAI `BaseTool` with the wrapped tool's name, description and
`args_schema`. Allowed calls run the original tool; a denial or approval comes back as the
tool's text output (the same messages as above), so the crew agent reads it. `wait=True`
waits for a person. The tests exercise the wrapper through `BaseTool.run` and
`to_structured_tool().invoke` with real CrewAI 1.15; a full crew run needs an LLM and is not
part of the suite. CrewAI's own dependencies need Python 3.11 or newer.

## MCP

AgentGuard is itself an MCP server at `/mcp` (streamable HTTP). Point any MCP client at it with
the agent's token; the client sees the tools of every registered MCP server it may use, named
`<server>.<tool>`, and every call goes through policy, approvals, limits, taint, output
scanning and audit. A denied call returns a tool error and never reaches the upstream server.

```python
from euron_agentguard.mcp import open_session, is_error

async with open_session(guard) as session:            # token refreshed automatically
    tools = await session.list_tools()
    result = await session.call_tool("notes.read_note", {"name": "todo"})
    if is_error(result): ...
```

`open_session` works with the `mcp` package 1.x (httpx) and 2.x (httpx2). For other clients,
`mcp_settings(guard)` returns `url` and `headers` (`Authorization`, and `X-AgentGuard-Run`
when a run id is set), with `.as_langchain()` for `langchain-mcp-adapters` and
`.as_client_config()` for an `mcpServers` JSON file. Those headers carry a token that expires
(15 minutes by default): regenerate them, or prefer `open_session`. In Node.js,
`guard.mcpSettings()` returns the same.

## FastAPI and Express: protect your own tool

When the tool is your own service, make it refuse calls AgentGuard did not allow. The agent
asks with `want_token=True` and sends the token in `X-AgentGuard-Decision`:

```python
@app.post("/refunds")
async def refund(body: Refund,
                 decision=Depends(require_decision(verifier, tool="refunds", action="create"))):
    ...
```

```ts
app.post("/refunds", express.json(), requireDecision(verifier, { tool: "refunds", action: "create" }), handler);
```

Both verify the signature, expiry, organisation, tool, action and the action hash of the
request body, then redeem the token once. See
[examples/fastapi-protected-tool](../../examples/fastapi-protected-tool/) and
[examples/node-quickstart](../../examples/node-quickstart/).

## AutoGen and other frameworks

Any framework that calls Python functions as tools can use the decorator. Decorate the
function, then register it as usual:

```python
from autogen_core.tools import FunctionTool

@guard.tool("refunds", "create")
async def refund(amount: int, customer: str) -> str:
    """Refund a customer."""
    return await payments.refund(amount, customer)

refund_tool = FunctionTool(refund, description="Refund a customer")
```

The decorator keeps the function's name, docstring and signature (`functools.wraps`), which is
what these frameworks read to build the tool schema. A denial raises `ActionDenied` and an
approval `ApprovalRequired`; frameworks that report tool exceptions to the model will show the
message. If yours does not, catch them and return `euron_agentguard.messages.decision_message(
exc.decision)`. This path is the generic decorator, which is unit and integration tested; the
AutoGen registration itself is not part of the test suite.
