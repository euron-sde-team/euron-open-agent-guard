"""What a model or a crew agent reads when AgentGuard did not allow a tool call."""

from __future__ import annotations

from euron_agentguard.models import BaseDecision


def decision_message(decision: BaseDecision) -> str:
    """The tool message a model reads when AgentGuard did not allow the call."""
    if decision.needs_approval and decision.approval is not None:
        return (
            f"AgentGuard: this action needs approval by a person and has not run "
            f"(approval {decision.approval.id}: {decision.reason}). Tell the user it is "
            f"waiting for approval at {decision.approval.url}. Once it is approved, call "
            f"the tool again with exactly the same arguments."
        )
    if decision.failed_closed and decision.reason_code == "guard_unavailable":
        return (
            "AgentGuard could not be reached, so this action was denied and has not run. "
            "Try again later."
        )
    return (
        f"AgentGuard denied this action ({decision.reason_code}): {decision.reason}. It "
        f"has not run. Do not retry it with the same arguments."
    )
