"""A LangGraph ReAct agent whose every tool call is decided by AgentGuard.

The chat model here is scripted (it replays the tool calls a real model would make), so the
example runs without an LLM key and always shows the same four outcomes. To use a real model,
replace ``ScriptedModel(...)`` with any LangChain chat model, for example
``ChatOpenAI(model="gpt-4o-mini")``: nothing else changes.

    python agent.py
"""

from __future__ import annotations

import os
import sys
from collections.abc import Sequence
from typing import Any

from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.tools import tool
from langgraph.prebuilt import create_react_agent

from euron_agentguard import AgentGuard, current_decision
from euron_agentguard.langgraph import guard_tools


@tool
def search(q: str) -> str:
    """Search the knowledge base."""
    return f"Policy: refunds up to 500 are automatic; larger ones need a manager ({q})."


@tool
def refunds(amount: int, customer: str) -> str:
    """Refund a customer."""
    decision = current_decision()  # the AgentGuard decision behind this call
    return f"Refunded {amount} to {customer} (decision {decision.decision_id if decision else '?'})"


@tool
def shell(command: str) -> str:
    """Run a shell command on the support server."""
    return "this never runs: policy denies it"


class ScriptedModel(GenericFakeChatModel):
    """Replays scripted messages; accepts tools like a real chat model."""

    def bind_tools(self, tools: Sequence[Any], **_: Any) -> ScriptedModel:
        return self


def call(name: str, args: dict[str, Any], n: int) -> dict[str, Any]:
    return {"name": name, "args": args, "id": f"call_{n}", "type": "tool_call"}


def main() -> int:
    guard = AgentGuard(
        os.environ.get("AGENTGUARD_URL", "http://localhost:5130"),
        os.environ["AGENTGUARD_CLIENT_ID"],
        os.environ["AGENTGUARD_CLIENT_SECRET"],
    )
    model = ScriptedModel(
        messages=iter(
            [
                AIMessage(content="", tool_calls=[
                    call("search", {"q": "refund policy"}, 1),
                    call("refunds", {"amount": 40, "customer": "c-2001"}, 2),
                    call("shell", {"command": "cat /etc/passwd"}, 3),
                    call("refunds", {"amount": 900, "customer": "c-2001"}, 4),
                ]),
                AIMessage(content="I refunded 40; the 900 refund is waiting for a manager."),
            ]
        )
    )
    tools = guard_tools(guard, [search, refunds, shell], actions={"refunds": "create"})
    agent = create_react_agent(model, tools)
    result = agent.invoke(
        {"messages": [("user", "The customer c-2001 wants their money back.")]},
        config={"configurable": {"thread_id": "support-ticket-2001"}},  # becomes the run id
    )
    outcomes = []
    for message in result["messages"]:
        if isinstance(message, ToolMessage):
            print(f"[{message.name}] {message.content}\n")
            outcomes.append(str(message.content))
    print(f"[agent] {result['messages'][-1].content}")
    guard.close()
    ok = (
        any(o.startswith("Refunded 40") for o in outcomes)
        and any("AgentGuard denied" in o for o in outcomes)
        and any("needs approval" in o for o in outcomes)
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
