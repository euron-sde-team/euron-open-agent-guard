"""The LangChain, CrewAI and MCP helpers with a mocked API."""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import httpx
import pytest
import respx
from langchain_core.tools import tool

from euron_agentguard import ActionDenied, AgentGuard, AsyncAgentGuard, current_decision
from euron_agentguard.langgraph import GuardedTool, guard_tool, guard_tools
from euron_agentguard.mcp import amcp_settings, gateway_url, mcp_settings
from euron_agentguard.messages import decision_message
from euron_agentguard.models import Decision

from .helpers import BASE, CLIENT_ID, CLIENT_SECRET, approval_status, decision, token_response

RAN: list[dict[str, Any]] = []


@tool
def refunds(amount: int, customer: str) -> str:
    """Refund a customer."""
    d = current_decision()
    RAN.append({"amount": amount, "customer": customer, "decision": d.decision if d else None})
    return f"Refunded {amount}"


@tool(response_format="content_and_artifact")
def report(q: str) -> tuple[str, dict[str, Any]]:
    """A report with an artifact."""
    return f"report {q}", {"rows": 1}


@pytest.fixture
def api() -> Iterator[respx.MockRouter]:
    RAN.clear()
    with respx.mock(base_url=BASE, assert_all_called=False) as router:
        router.post("/oauth/token").mock(return_value=httpx.Response(200, json=token_response()))
        yield router


@pytest.fixture
def guard() -> Iterator[AgentGuard]:
    with AgentGuard(BASE, CLIENT_ID, CLIENT_SECRET) as g:
        yield g


def _sent(route: respx.Route) -> Any:
    return json.loads(route.calls.last.request.content)


def test_wrapped_tool_keeps_its_interface(guard: AgentGuard) -> None:
    wrapped = guard_tool(guard, refunds, name="payments.refund", action="create")
    assert isinstance(wrapped, GuardedTool)
    assert wrapped.name == "refunds" and wrapped.description == refunds.description
    assert wrapped.args == refunds.args
    assert wrapped.agentguard_tool == "payments.refund"
    with pytest.raises(ValueError, match="already guarded"):
        guard_tool(guard, wrapped)


def test_allowed_runs_the_tool(api: respx.MockRouter, guard: AgentGuard) -> None:
    route = api.post("/api/v1/authorize").mock(return_value=httpx.Response(200, json=decision()))
    [wrapped] = guard_tools(
        guard, [refunds], actions={"refunds": "create"}, names={"refunds": "payments"}
    )
    out = wrapped.invoke(
        {"amount": 5, "customer": "c1"}, config={"configurable": {"thread_id": "thread 1/x"}}
    )
    assert out == "Refunded 5"
    assert RAN == [{"amount": 5, "customer": "c1", "decision": "allow"}]
    sent = _sent(route)
    assert sent["tool"] == "payments" and sent["action"] == "create"
    assert sent["parameters"] == {"amount": 5, "customer": "c1"}
    assert sent["run_id"] == "thread-1/x"


def test_denied_and_held_return_messages(api: respx.MockRouter, guard: AgentGuard) -> None:
    route = api.post("/api/v1/authorize").mock(
        return_value=httpx.Response(200, json=decision("deny"))
    )
    wrapped = guard_tool(guard, refunds)
    assert "AgentGuard denied this action (policy_deny)" in wrapped.invoke(
        {"amount": 5, "customer": "c1"}
    )
    route.mock(return_value=httpx.Response(200, json=decision("require_approval")))
    assert "needs approval by a person" in wrapped.invoke({"amount": 5, "customer": "c1"})
    route.mock(side_effect=httpx.ConnectError("down"))
    assert "could not be reached" in wrapped.invoke({"amount": 5, "customer": "c1"})
    assert RAN == []
    strict = guard_tool(guard, refunds, raise_on_deny=True)
    route.mock(side_effect=None, return_value=httpx.Response(200, json=decision("deny")))
    with pytest.raises(ActionDenied):
        strict.invoke({"amount": 5, "customer": "c1"})


def test_wait_then_run(api: respx.MockRouter, guard: AgentGuard) -> None:
    held = decision("require_approval")
    api.post("/api/v1/authorize").mock(
        side_effect=[httpx.Response(200, json=held), httpx.Response(200, json=decision())]
    )
    api.get(f"/api/v1/approvals/{held['approval']['id']}/status").mock(
        return_value=httpx.Response(200, json=approval_status("approved"))
    )
    wrapped = guard_tool(guard, refunds, wait=True)
    assert wrapped.invoke({"amount": 900, "customer": "c1"}) == "Refunded 900"


def test_execute_mode_and_artifacts(api: respx.MockRouter, guard: AgentGuard) -> None:
    api.post("/api/v1/execute").mock(
        return_value=httpx.Response(
            200, json=decision(executed=True, result="remote result", result_meta={"bytes": 13})
        )
    )
    wrapped = guard_tool(guard, refunds, execute=True)
    assert wrapped.invoke({"amount": 1, "customer": "c"}) == "remote result"
    assert RAN == []  # AgentGuard ran it, not the local function
    rep = guard_tool(guard, report, execute=True)
    call = {"name": "report", "args": {"q": "x"}, "id": "c1", "type": "tool_call"}
    message = rep.invoke(call)
    assert message.content == "remote result" and message.artifact == {"bytes": 13}
    api.post("/api/v1/authorize").mock(return_value=httpx.Response(200, json=decision("deny")))
    denied = guard_tool(guard, report).invoke(call)
    assert "denied" in denied.content and denied.artifact is None
    allowed = guard_tool(guard, report)
    api.post("/api/v1/authorize").mock(return_value=httpx.Response(200, json=decision()))
    assert allowed.invoke(call).artifact == {"rows": 1}


def test_async_guard_requires_ainvoke(api: respx.MockRouter) -> None:
    g = AsyncAgentGuard(BASE, CLIENT_ID, CLIENT_SECRET)
    wrapped = guard_tool(g, refunds)
    with pytest.raises(TypeError, match="ainvoke"):
        wrapped.invoke({"amount": 1, "customer": "c"})


async def test_ainvoke_with_both_guards(api: respx.MockRouter, guard: AgentGuard) -> None:
    held = decision("require_approval")
    api.post("/api/v1/authorize").mock(
        side_effect=[
            httpx.Response(200, json=decision()),
            httpx.Response(200, json=held),
            httpx.Response(200, json=decision()),
            httpx.Response(200, json=decision("deny")),
        ]
    )
    api.get(f"/api/v1/approvals/{held['approval']['id']}/status").mock(
        return_value=httpx.Response(200, json=approval_status("approved"))
    )
    assert await guard_tool(guard, refunds).ainvoke({"amount": 1, "customer": "c"}) == "Refunded 1"
    async with AsyncAgentGuard(BASE, CLIENT_ID, CLIENT_SECRET, run_id="fixed") as g:
        wrapped = guard_tool(g, refunds, wait=True)
        assert await wrapped.ainvoke({"amount": 2, "customer": "c"}) == "Refunded 2"
        assert "denied" in await wrapped.ainvoke({"amount": 3, "customer": "c"})
        api.post("/api/v1/execute").mock(
            return_value=httpx.Response(200, json=decision(executed=True, result="r"))
        )
        assert (
            await guard_tool(g, refunds, execute=True).ainvoke({"amount": 4, "customer": "c"})
            == "r"
        )


def test_messages() -> None:
    base: dict[str, Any] = {"tool": "t", "action": "call", "reason": "Too large"}
    deny = Decision(decision="deny", allowed=False, reason_code="policy_deny", **base)
    assert decision_message(deny).startswith("AgentGuard denied this action (policy_deny)")


def test_crewai_wrapper(api: respx.MockRouter, guard: AgentGuard) -> None:
    crewai_tools = pytest.importorskip("crewai.tools")
    from euron_agentguard.crewai import guard_crew_tool

    calls: list[int] = []

    class Refund(crewai_tools.BaseTool):  # type: ignore[misc, name-defined]
        name: str = "refunds"
        description: str = "Refund"

        def _run(self, amount: int) -> str:
            calls.append(amount)
            return "ok"

    held = decision("require_approval")
    route = api.post("/api/v1/authorize").mock(
        side_effect=[
            httpx.Response(200, json=decision()),
            httpx.Response(200, json=decision("deny")),
            httpx.Response(200, json=held),
            httpx.Response(200, json=decision()),
            httpx.Response(200, json=decision("deny")),
        ]
    )
    api.get(f"/api/v1/approvals/{held['approval']['id']}/status").mock(
        return_value=httpx.Response(200, json=approval_status("approved"))
    )
    wrapped = guard_crew_tool(guard, Refund(), action="create")
    assert wrapped.run(amount=1) == "ok"
    assert "denied" in wrapped.run(amount=2)
    waiting = guard_crew_tool(guard, Refund(), wait=True)
    assert waiting.run(amount=3) == "ok"
    assert _sent(route)["approval_id"] == held["approval"]["id"]
    strict = guard_crew_tool(guard, Refund(), raise_on_deny=True)
    with pytest.raises(ActionDenied):
        strict.run(amount=4)
    with pytest.raises(TypeError):
        strict._run(5)
    assert calls == [1, 3]


async def test_mcp_settings(api: respx.MockRouter, guard: AgentGuard) -> None:
    settings = mcp_settings(guard, run_id="r1")
    assert settings.url == f"{BASE}/mcp" == gateway_url(guard)
    assert settings.headers == {"Authorization": "Bearer agent-token-1", "X-AgentGuard-Run": "r1"}
    assert settings.as_client_config()["mcpServers"]["agentguard"]["type"] == "http"
    assert settings.as_langchain()["url"] == f"{BASE}/mcp"
    async with AsyncAgentGuard(BASE, CLIENT_ID, CLIENT_SECRET) as g:
        a = await amcp_settings(g)
    assert a.headers == {"Authorization": "Bearer agent-token-1"}
