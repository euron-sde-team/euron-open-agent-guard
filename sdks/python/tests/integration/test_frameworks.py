"""Framework integrations against a real API: a LangGraph agent (real langgraph, a scripted
chat model) and a CrewAI tool, each allowed, denied and held for approval by policy."""

from __future__ import annotations

import secrets
import threading
from collections.abc import Iterator, Sequence
from typing import Any

import pytest
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.tools import tool
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode, create_react_agent

from euron_agentguard import AgentGuard, AsyncAgentGuard, current_decision
from euron_agentguard.langgraph import guard_tools

from .conftest import URL, Admin, Credential

CALLS: list[tuple[str, dict[str, Any]]] = []


@tool
def refunds(amount: int, customer: str) -> str:
    """Refund a customer."""
    decision = current_decision()
    assert decision is not None and decision.allowed
    CALLS.append(("refunds", {"amount": amount, "customer": customer}))
    return f"Refunded {amount} to {customer}"


@tool
def shell(command: str) -> str:
    """Run a shell command."""
    CALLS.append(("shell", {"command": command}))
    return "ran"


@tool
def search(q: str) -> str:
    """Search the knowledge base."""
    CALLS.append(("search", {"q": q}))
    return f"3 results for {q}"


class ScriptedModel(GenericFakeChatModel):
    """A chat model that replays scripted messages and accepts tools (like a real one)."""

    def bind_tools(self, tools: Sequence[Any], **_: Any) -> ScriptedModel:
        return self


def _call(name: str, args: dict[str, Any]) -> dict[str, Any]:
    return {"name": name, "args": args, "id": f"call_{secrets.token_hex(4)}", "type": "tool_call"}


def _model(*turns: list[dict[str, Any]]) -> ScriptedModel:
    messages: list[AIMessage] = [AIMessage(content="", tool_calls=t) for t in turns]
    messages.append(AIMessage(content="All done."))
    return ScriptedModel(messages=iter(messages))


def _tool_graph(node: ToolNode) -> Any:
    """A graph that is only a ToolNode (ToolNode runs inside a graph runtime)."""
    graph = StateGraph(MessagesState)
    graph.add_node("tools", node)
    graph.add_edge(START, "tools")
    graph.add_edge("tools", END)
    return graph.compile()


@pytest.fixture
def langgraph_guard(admin: Admin) -> Iterator[tuple[AgentGuard, Credential]]:
    c = admin.agent(f"lg-{secrets.token_hex(3)}", ["support"], framework="langgraph")
    with AgentGuard(URL, c.client_id, c.client_secret) as g:
        yield g, c


def test_langgraph_agent_allowed_denied_and_held(
    langgraph_guard: tuple[AgentGuard, Credential],
) -> None:
    guard, _ = langgraph_guard
    CALLS.clear()
    customer = f"c-{secrets.token_hex(3)}"
    model = _model(
        [
            _call("search", {"q": "refund policy"}),
            _call("refunds", {"amount": 40, "customer": customer}),
            _call("shell", {"command": "cat /etc/passwd"}),
            _call("refunds", {"amount": 900, "customer": customer}),
        ]
    )
    agent = create_react_agent(
        model, guard_tools(guard, [search, refunds, shell], actions={"refunds": "create"})
    )
    result = agent.invoke(
        {"messages": [("user", "Help this customer")]},
        config={"configurable": {"thread_id": f"thread-{customer}"}},
    )
    outputs = list(result["messages"])
    tool_messages = [m for m in outputs if isinstance(m, ToolMessage)]
    by_call = {m.tool_call_id: str(m.content) for m in tool_messages}
    contents = list(by_call.values())
    assert len(tool_messages) == 4
    assert "3 results for refund policy" in contents
    assert f"Refunded 40 to {customer}" in contents
    assert any("AgentGuard denied this action (policy_deny)" in c for c in contents)
    assert any("needs approval by a person" in c for c in contents)
    # Only the allowed calls reached the real tools.
    assert [
        ("search", {"q": "refund policy"}),
        ("refunds", {"amount": 40, "customer": customer}),
    ] == CALLS
    assert result["messages"][-1].content == "All done."


def test_langgraph_thread_id_becomes_run(
    langgraph_guard: tuple[AgentGuard, Credential], admin: Admin
) -> None:
    guard, c = langgraph_guard
    thread = f"thread-{secrets.token_hex(4)}"
    graph = _tool_graph(ToolNode(guard_tools(guard, [search])))
    graph.invoke(
        {"messages": [AIMessage(content="", tool_calls=[_call("search", {"q": "x"})])]},
        config={"configurable": {"thread_id": thread}},
    )
    runs = admin.call("GET", f"/api/v1/runs?agent_id={c.agent_id}")
    assert any(r["run_key"] == thread for r in runs)


def test_langgraph_wait_for_approval(
    langgraph_guard: tuple[AgentGuard, Credential], admin: Admin
) -> None:
    guard, _ = langgraph_guard
    CALLS.clear()
    customer = f"c-{secrets.token_hex(3)}"

    def approve() -> None:
        import time

        for _ in range(50):
            pending = admin.call("GET", "/api/v1/approvals?status=pending")
            match = [a for a in pending if a["resource"] == f"customer:{customer}"]
            if match:
                admin.approve(match[0]["id"])
                return
            time.sleep(0.2)

    thread = threading.Thread(target=approve)
    thread.start()
    graph = _tool_graph(
        ToolNode(
            guard_tools(guard, [refunds], actions={"refunds": "create"}, wait=True, wait_timeout=20)
        )
    )
    out = graph.invoke(
        {
            "messages": [
                AIMessage(
                    content="", tool_calls=[_call("refunds", {"amount": 950, "customer": customer})]
                )
            ]
        }
    )
    thread.join()
    assert str(out["messages"][-1].content) == f"Refunded 950 to {customer}"
    assert [("refunds", {"amount": 950, "customer": customer})] == CALLS


async def test_langgraph_async_agent(admin: Admin) -> None:
    c = admin.agent(f"lga-{secrets.token_hex(3)}", ["support"], framework="langgraph")
    CALLS.clear()
    async with AsyncAgentGuard(URL, c.client_id, c.client_secret) as guard:
        model = _model([_call("search", {"q": "async"}), _call("shell", {"command": "ls"})])
        agent = create_react_agent(model, guard_tools(guard, [search, shell]))
        result = await agent.ainvoke({"messages": [("user", "go")]})
    contents = [str(m.content) for m in result["messages"] if isinstance(m, ToolMessage)]
    assert "3 results for async" in contents
    assert any("AgentGuard denied" in c for c in contents)
    assert CALLS == [("search", {"q": "async"})]


def test_crewai_tool_wrapper(admin: Admin) -> None:
    crewai_tools = pytest.importorskip("crewai.tools")
    from euron_agentguard.crewai import GuardedCrewTool, guard_crew_tool

    ran: list[dict[str, Any]] = []

    class RefundTool(crewai_tools.BaseTool):  # type: ignore[misc, name-defined]
        name: str = "refunds"
        description: str = "Refund a customer"

        def _run(self, amount: int, customer: str) -> str:
            ran.append({"amount": amount, "customer": customer})
            return f"Refunded {amount}"

    c = admin.agent(f"crew-{secrets.token_hex(3)}", ["support"], framework="crewai")
    customer = f"c-{secrets.token_hex(3)}"
    with AgentGuard(URL, c.client_id, c.client_secret) as guard:
        wrapped = guard_crew_tool(guard, RefundTool(), action="create")
        assert isinstance(wrapped, GuardedCrewTool)
        assert isinstance(wrapped, crewai_tools.BaseTool)
        assert wrapped.name == "refunds"
        assert set(wrapped.args_schema.model_fields) == {"amount", "customer"}
        assert wrapped.run(amount=30, customer=customer) == "Refunded 30"
        denied = wrapped.run(amount=20000, customer=customer)
        assert "AgentGuard denied this action (policy_deny)" in denied
        held = wrapped.run(amount=700, customer=customer)
        assert "needs approval by a person" in held
        # The structured form CrewAI agents actually call goes through the same guard.
        structured = wrapped.to_structured_tool()
        assert structured.invoke({"amount": 31, "customer": customer}) == "Refunded 31"
    assert ran == [{"amount": 30, "customer": customer}, {"amount": 31, "customer": customer}]
