# LangGraph agent

A `create_react_agent` agent whose four tool calls get four outcomes from policy: a search and
a small refund run, a shell command is denied, a large refund waits for a person. The model
reads AgentGuard's answer as the tool message, so it can tell the user what happened.

```bash
pip install "./sdks/python[langgraph]"
eval "$(uv run --with httpx python examples/bootstrap.py)"
python examples/langgraph-agent/agent.py
```

The chat model is scripted so the example needs no LLM key. Swap `ScriptedModel(...)` for any
LangChain chat model (for example `ChatOpenAI(model="gpt-4o-mini")`); `guard_tools` does not
change. LangGraph 1.x prints a deprecation notice for `langgraph.prebuilt.create_react_agent`
(it moved to `langchain.agents.create_agent`); guarded tools work with both.
