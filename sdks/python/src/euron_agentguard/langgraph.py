"""LangChain and LangGraph: every tool call is authorized by AgentGuard before it runs.

::

    from euron_agentguard.langgraph import guard_tools

    tools = guard_tools(guard, [search, refund])
    agent = create_react_agent(model, tools)          # or ToolNode(tools) in your own graph

A wrapped tool keeps its name, description and argument schema, so the model sees exactly
the same tool. On each call it asks AgentGuard with the tool's arguments as parameters:

* allowed: the original tool runs (``current_decision()`` inside it returns the decision);
* denied: the tool does not run; the model receives a tool message saying why;
* approval required: the tool does not run; the model receives a tool message naming the
  approval, so it can tell the user. With ``wait=True`` the call blocks until a person
  decides, then runs only if AgentGuard now allows it.

``execute=True`` lets AgentGuard run the tool itself (http, MCP and sandbox tools registered
in AgentGuard), so the agent process never holds that tool's credentials.

The LangGraph thread id (``config["configurable"]["thread_id"]``) is used as the run id
when neither the guard nor the call sets one, so limits and taint follow the conversation.

Requires the ``langgraph`` extra (``pip install euron-agentguard[langgraph]``).
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Mapping, Sequence
from typing import Any

from langchain_core.callbacks import (
    AsyncCallbackManagerForToolRun,
    CallbackManagerForToolRun,
)
from langchain_core.runnables import RunnableConfig
from langchain_core.tools import BaseTool
from pydantic import ConfigDict

from euron_agentguard import _core
from euron_agentguard.aio import AsyncAgentGuard
from euron_agentguard.client import AgentGuard
from euron_agentguard.errors import ActionDenied
from euron_agentguard.messages import decision_message
from euron_agentguard.models import BaseDecision

_RUN_UNSAFE = re.compile(r"[^A-Za-z0-9_.:@/-]")


def _run_id(config: RunnableConfig | None) -> str | None:
    configurable = (config or {}).get("configurable") or {}
    thread = configurable.get("thread_id")
    if thread is None:
        return None
    return _RUN_UNSAFE.sub("-", str(thread))[:128] or None


class GuardedTool(BaseTool):
    """A LangChain tool that asks AgentGuard before every call. Build with ``guard_tool``."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    inner: BaseTool
    guard: AgentGuard | AsyncAgentGuard
    agentguard_tool: str
    agentguard_action: str = "call"
    resource: str | None = None
    wait: bool = False
    wait_timeout: float = 300.0
    execute: bool = False
    raise_on_deny: bool = False

    def _params(self, kwargs: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in kwargs.items() if k not in ("run_manager", "callbacks")}

    def _as_call(self, params: dict[str, Any]) -> dict[str, Any]:
        # Invoked as a tool call, the inner tool returns content and artifact together.
        return {"name": self.inner.name, "args": params, "id": "agentguard", "type": "tool_call"}

    def _run_for(self, config: RunnableConfig | None) -> str | None:
        return None if self.guard.run_id else _run_id(config)

    def _refused(self, decision: BaseDecision) -> Any:
        if self.raise_on_deny:
            decision.raise_for_decision()
        message = decision_message(decision)
        return (message, None) if self.response_format == "content_and_artifact" else message

    def _result(self, decision: BaseDecision) -> Any:
        if self.response_format == "content_and_artifact":
            return decision.result, decision.result_meta
        return decision.result

    def _decide_sync(self, params: dict[str, Any], run_id: str | None) -> BaseDecision:
        guard = self.guard
        assert isinstance(guard, AgentGuard)
        call = guard.execute if self.execute else guard.authorize
        decision: BaseDecision = call(
            self.agentguard_tool, self.agentguard_action, self.resource, params, run_id=run_id
        )
        if decision.needs_approval and self.wait and decision.approval is not None:
            status = guard.wait_for_approval(decision.approval.id, self.wait_timeout)
            if not status.pending:
                decision = call(
                    self.agentguard_tool,
                    self.agentguard_action,
                    self.resource,
                    params,
                    run_id=run_id,
                    approval_id=decision.approval.id,
                )
        return decision

    async def _decide_async(self, params: dict[str, Any], run_id: str | None) -> BaseDecision:
        guard = self.guard
        if isinstance(guard, AgentGuard):
            return await asyncio.to_thread(self._decide_sync, params, run_id)
        call = guard.execute if self.execute else guard.authorize
        decision: BaseDecision = await call(
            self.agentguard_tool, self.agentguard_action, self.resource, params, run_id=run_id
        )
        if decision.needs_approval and self.wait and decision.approval is not None:
            status = await guard.wait_for_approval(decision.approval.id, self.wait_timeout)
            if not status.pending:
                decision = await call(
                    self.agentguard_tool,
                    self.agentguard_action,
                    self.resource,
                    params,
                    run_id=run_id,
                    approval_id=decision.approval.id,
                )
        return decision

    def _run(
        self,
        config: RunnableConfig,
        run_manager: CallbackManagerForToolRun | None = None,
        **kwargs: Any,
    ) -> Any:
        if isinstance(self.guard, AsyncAgentGuard):
            raise TypeError("This tool is guarded by AsyncAgentGuard: invoke it with ainvoke")
        params = self._params(kwargs)
        decision = self._decide_sync(params, self._run_for(config))
        if not decision.allowed:
            return self._refused(decision)
        if self.execute:
            return self._result(decision)
        token = _core.set_current(decision)
        try:
            config_out: RunnableConfig = {
                "callbacks": run_manager.get_child() if run_manager else None
            }
            if self.response_format == "content_and_artifact":
                message = self.inner.invoke(self._as_call(params), config=config_out)
                return message.content, message.artifact
            return self.inner.invoke(params, config=config_out)
        finally:
            _core.reset_current(token)

    async def _arun(
        self,
        config: RunnableConfig,
        run_manager: AsyncCallbackManagerForToolRun | None = None,
        **kwargs: Any,
    ) -> Any:
        params = self._params(kwargs)
        decision = await self._decide_async(params, self._run_for(config))
        if not decision.allowed:
            return self._refused(decision)
        if self.execute:
            return self._result(decision)
        token = _core.set_current(decision)
        try:
            config_out: RunnableConfig = {
                "callbacks": run_manager.get_child() if run_manager else None
            }
            if self.response_format == "content_and_artifact":
                message = await self.inner.ainvoke(self._as_call(params), config=config_out)
                return message.content, message.artifact
            return await self.inner.ainvoke(params, config=config_out)
        finally:
            _core.reset_current(token)


def guard_tool(
    guard: AgentGuard | AsyncAgentGuard,
    tool: BaseTool,
    *,
    name: str | None = None,
    action: str = "call",
    resource: str | None = None,
    wait: bool = False,
    wait_timeout: float = 300.0,
    execute: bool = False,
    raise_on_deny: bool = False,
) -> GuardedTool:
    """Wrap one LangChain tool. ``name`` is its AgentGuard tool name (default: the same)."""
    if isinstance(tool, GuardedTool):
        raise ValueError(f"{tool.name} is already guarded")
    return GuardedTool(
        name=tool.name,
        description=tool.description,
        args_schema=tool.args_schema,
        return_direct=tool.return_direct,
        response_format=tool.response_format,
        inner=tool,
        guard=guard,
        agentguard_tool=name or tool.name,
        agentguard_action=action,
        resource=resource,
        wait=wait,
        wait_timeout=wait_timeout,
        execute=execute,
        raise_on_deny=raise_on_deny,
    )


def guard_tools(
    guard: AgentGuard | AsyncAgentGuard,
    tools: Sequence[BaseTool],
    *,
    names: Mapping[str, str] | None = None,
    actions: Mapping[str, str] | None = None,
    wait: bool = False,
    wait_timeout: float = 300.0,
    execute: bool = False,
    raise_on_deny: bool = False,
) -> list[GuardedTool]:
    """Wrap every tool. ``names`` and ``actions`` map a LangChain tool name to its
    AgentGuard tool name and action (defaults: the same name, action ``call``)."""
    names = names or {}
    actions = actions or {}
    return [
        guard_tool(
            guard,
            t,
            name=names.get(t.name),
            action=actions.get(t.name, "call"),
            wait=wait,
            wait_timeout=wait_timeout,
            execute=execute,
            raise_on_deny=raise_on_deny,
        )
        for t in tools
    ]


__all__ = ["ActionDenied", "GuardedTool", "decision_message", "guard_tool", "guard_tools"]
