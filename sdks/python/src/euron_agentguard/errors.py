"""Exceptions the SDK raises.

``authorize``, ``execute`` and ``ask_person`` never raise for a failure to decide: they return
a denied :class:`~euron_agentguard.models.Decision` (fail closed). The exceptions below are
for code that wants an exception instead (``raise_for_decision``, the ``tool`` decorator),
for the calls that have no decision to return (``scan``, approval status, ``end_run``), and
for resource-side verification.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from euron_agentguard.models import ApprovalInfo, BaseDecision


class AgentGuardError(Exception):
    """Base class of every SDK exception."""


class APIError(AgentGuardError):
    """AgentGuard answered with an error (``{"error": {"code", "message", "details"}}``)."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        code: str = "api_error",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.code = code
        self.details = details or {}

    def __repr__(self) -> str:
        return f"{type(self).__name__}(status_code={self.status_code!r}, code={self.code!r})"


class GuardUnavailable(APIError):  # noqa: N818 (the name says what happened)
    """AgentGuard could not be reached or could not decide (connection error, timeout, 5xx)."""


class ActionDenied(AgentGuardError):  # noqa: N818
    """The action was not allowed. ``decision`` explains why."""

    def __init__(self, decision: BaseDecision) -> None:
        super().__init__(f"{decision.tool}.{decision.action} denied: {decision.reason}")
        self.decision = decision

    @property
    def reason_code(self) -> str:
        return self.decision.reason_code


class ApprovalRequired(ActionDenied):
    """The action waits for a person. ``approval`` names the request to wait on.

    It is a subclass of :class:`ActionDenied` because, until a person approves, the action
    must not run: code that catches ``ActionDenied`` to skip an action skips this one too.
    """

    def __init__(self, decision: BaseDecision) -> None:
        super().__init__(decision)
        self.args = (
            f"{decision.tool}.{decision.action} needs approval: {decision.reason}"
            + (f" (approval {decision.approval.id})" if decision.approval else ""),
        )

    @property
    def approval(self) -> ApprovalInfo | None:
        return self.decision.approval


class DecisionRejected(AgentGuardError):  # noqa: N818
    """A decision token failed verification on the resource side. ``reason`` is a code:

    ``missing_token``, ``malformed``, ``invalid_or_expired``, ``unknown_key``, ``wrong_org``,
    ``wrong_agent``, ``tool_mismatch``, ``action_mismatch``, ``resource_mismatch``,
    ``params_mismatch``, ``already_used`` or ``guard_unavailable``.
    """

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message
