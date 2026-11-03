"""CrewAI: a ``BaseTool`` wrapper that asks AgentGuard before the tool runs.

::

    from euron_agentguard.crewai import guard_crew_tool

    refund = guard_crew_tool(guard, RefundTool(), name="refunds", action="create")
    agent = Agent(role="Support", goal="...", backstory="...", tools=[refund])

The wrapper keeps the tool's name, description and argument schema. When AgentGuard does
not allow the call the tool does not run and the agent receives a message saying why (or,
for an approval, which approval it waits on); ``wait=True`` blocks until a person decides.

Requires the ``crewai`` extra (``pip install euron-agentguard[crewai]``).
"""

from __future__ import annotations

from typing import Any

from crewai.tools import BaseTool
from pydantic import ConfigDict

from euron_agentguard import _core
from euron_agentguard.client import AgentGuard
from euron_agentguard.messages import decision_message
from euron_agentguard.models import BaseDecision


class GuardedCrewTool(BaseTool):
    """A CrewAI tool that is authorized by AgentGuard on every call."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    inner: BaseTool
    guard: AgentGuard
    agentguard_tool: str
    agentguard_action: str = "call"
    resource: str | None = None
    wait: bool = False
    wait_timeout: float = 300.0
    raise_on_deny: bool = False

    def _decide(self, params: dict[str, Any]) -> BaseDecision:
        decision: BaseDecision = self.guard.authorize(
            self.agentguard_tool, self.agentguard_action, self.resource, params
        )
        if decision.needs_approval and self.wait and decision.approval is not None:
            status = self.guard.wait_for_approval(decision.approval.id, self.wait_timeout)
            if not status.pending:
                decision = self.guard.authorize(
                    self.agentguard_tool,
                    self.agentguard_action,
                    self.resource,
                    params,
                    approval_id=decision.approval.id,
                )
        return decision

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        if args:
            raise TypeError(f"{self.name} takes keyword arguments only")
        decision = self._decide(dict(kwargs))
        if not decision.allowed:
            if self.raise_on_deny:
                decision.raise_for_decision()
            return decision_message(decision)
        token = _core.set_current(decision)
        try:
            return self.inner.run(**kwargs)
        finally:
            _core.reset_current(token)


def guard_crew_tool(
    guard: AgentGuard,
    tool: BaseTool,
    *,
    name: str | None = None,
    action: str = "call",
    resource: str | None = None,
    wait: bool = False,
    wait_timeout: float = 300.0,
    raise_on_deny: bool = False,
) -> GuardedCrewTool:
    """Wrap a CrewAI tool. ``name`` is its AgentGuard tool name (default: the same)."""
    return GuardedCrewTool(
        name=tool.name,
        description=tool.description,
        args_schema=tool.args_schema,
        result_as_answer=tool.result_as_answer,
        inner=tool,
        guard=guard,
        agentguard_tool=name or tool.name,
        agentguard_action=action,
        resource=resource,
        wait=wait,
        wait_timeout=wait_timeout,
        raise_on_deny=raise_on_deny,
    )


__all__ = ["GuardedCrewTool", "guard_crew_tool"]
