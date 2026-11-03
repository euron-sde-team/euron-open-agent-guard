"""The typed results of the agent runtime API.

They mirror ``AuthorizeResponse``, ``ExecuteResponse``, ``ScanResponse`` and the approval
status of ``docs/api/openapi.yaml``. Unknown fields the API adds later are kept in ``raw``.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal, TypeVar

from euron_agentguard.errors import ActionDenied, ApprovalRequired

DecisionValue = Literal["allow", "deny", "require_approval", "restrict", "quarantine"]
FINAL_APPROVAL_STATUSES = frozenset(
    {"approved", "rejected", "changes_requested", "expired", "revoked", "executed", "failed"}
)

_D = TypeVar("_D", bound="BaseDecision")


def parse_time(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


@dataclass(frozen=True)
class ApprovalInfo:
    """The approval request a ``require_approval`` decision created (or found)."""

    id: str
    status: str
    expires_at: datetime | None
    url: str
    required: list[dict[str, Any]] = field(default_factory=list)
    comment: str | None = None

    @classmethod
    def from_api(cls, data: Mapping[str, Any]) -> ApprovalInfo:
        return cls(
            id=str(data.get("id", "")),
            status=str(data.get("status", "pending")),
            expires_at=parse_time(data.get("expires_at")),
            url=str(data.get("url", "")),
            required=list(data.get("required") or []),
            comment=data.get("comment"),
        )


@dataclass(frozen=True)
class ApprovalStatus:
    """Where an approval request stands (``GET /api/v1/approvals/{id}/status``)."""

    id: str
    status: str
    comment: str | None = None
    expires_at: datetime | None = None
    decided_at: datetime | None = None
    result: dict[str, Any] | None = None

    @property
    def approved(self) -> bool:
        return self.status == "approved"

    @property
    def pending(self) -> bool:
        return self.status == "pending"

    @property
    def final(self) -> bool:
        return self.status in FINAL_APPROVAL_STATUSES

    @classmethod
    def from_api(cls, data: Mapping[str, Any]) -> ApprovalStatus:
        return cls(
            id=str(data.get("id", "")),
            status=str(data.get("status", "pending")),
            comment=data.get("comment"),
            expires_at=parse_time(data.get("expires_at")),
            decided_at=parse_time(data.get("decided_at")),
            result=data.get("result"),
        )


@dataclass(frozen=True)
class BaseDecision:
    """One decision. ``allowed`` is the only field that says whether to act.

    ``decision`` is the enforced outcome; in audit mode it is ``allow`` while ``would_be``
    says what enforce mode would have decided. A decision the SDK made itself because
    AgentGuard could not be asked (fail closed) has ``decision_id`` None, ``reason_code``
    ``guard_unavailable`` (or the API's error code) and the failure in ``error``.
    """

    decision: DecisionValue
    allowed: bool
    reason_code: str
    reason: str
    tool: str
    action: str
    decision_id: str | None = None
    would_be: DecisionValue = "deny"
    mode: Literal["enforce", "audit"] = "enforce"
    reasons: list[Any] = field(default_factory=list)
    policy_id: str | None = None
    policy: str | None = None
    policy_version: int | None = None
    obligations: dict[str, Any] = field(default_factory=dict)
    risk: dict[str, Any] = field(default_factory=dict)
    data_classes: list[str] = field(default_factory=list)
    action_hash: str | None = None
    approval: ApprovalInfo | None = None
    decision_token: str | None = None
    expires_at: datetime | None = None
    run_id: str | None = None
    # Set by execute: whether AgentGuard ran the tool, and its (obligation-applied) result.
    executed: bool = False
    result: Any = None
    result_meta: dict[str, Any] = field(default_factory=dict)
    # Set when the SDK failed closed: what went wrong.
    error: dict[str, Any] | None = None
    raw: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @property
    def needs_approval(self) -> bool:
        """True when a person must approve before this exact action may run."""
        return self.decision == "require_approval"

    @property
    def denied(self) -> bool:
        return not self.allowed

    @property
    def restricted(self) -> bool:
        """Allowed, with obligations (row limits, redactions) the tool must honour."""
        return self.allowed and self.decision == "restrict"

    @property
    def failed_closed(self) -> bool:
        """The SDK denied because AgentGuard could not be asked or answered with an error."""
        return self.error is not None

    def raise_for_decision(self: _D) -> _D:
        """Return the decision when allowed; raise :class:`ApprovalRequired` or
        :class:`ActionDenied` otherwise."""
        if self.allowed:
            return self
        if self.needs_approval:
            raise ApprovalRequired(self)
        raise ActionDenied(self)


@dataclass(frozen=True)
class Decision(BaseDecision):
    """A decision from :class:`~euron_agentguard.AgentGuard` (synchronous)."""

    _waiter: Callable[[str, float], ApprovalStatus] | None = field(
        default=None, repr=False, compare=False
    )

    def wait_for_approval(self, timeout: float = 300.0) -> ApprovalStatus:
        """Block until a person decides the approval (or ``timeout`` seconds pass).

        Returns the status; ``status.approved`` means the same call may now be retried and
        AgentGuard allows it once. Raises ``ValueError`` when the decision has no approval.
        """
        if self.approval is None or self._waiter is None:
            raise ValueError("This decision has no approval to wait for")
        return self._waiter(self.approval.id, timeout)


@dataclass(frozen=True)
class AsyncDecision(BaseDecision):
    """A decision from :class:`~euron_agentguard.AsyncAgentGuard`."""

    _waiter: Callable[[str, float], Awaitable[ApprovalStatus]] | None = field(
        default=None, repr=False, compare=False
    )

    async def wait_for_approval(self, timeout: float = 300.0) -> ApprovalStatus:
        """Wait until a person decides the approval (or ``timeout`` seconds pass)."""
        if self.approval is None or self._waiter is None:
            raise ValueError("This decision has no approval to wait for")
        return await self._waiter(self.approval.id, timeout)


def decision_fields(
    data: Mapping[str, Any], tool: str, action: str, *, error: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Keyword arguments for a decision class from an API response body."""
    decision = data.get("decision")
    if decision not in ("allow", "deny", "require_approval", "restrict", "quarantine"):
        decision = "deny"
    approval = data.get("approval")
    allowed = bool(data.get("allowed")) and decision in ("allow", "restrict")
    return {
        "decision": decision,
        "allowed": allowed,
        "reason_code": str(data.get("reason_code") or "unknown"),
        "reason": str(data.get("reason") or ""),
        "tool": tool,
        "action": action,
        "decision_id": str(data["decision_id"]) if data.get("decision_id") else None,
        "would_be": data.get("would_be") or decision,
        "mode": "audit" if data.get("mode") == "audit" else "enforce",
        "reasons": list(data.get("reasons") or []),
        "policy_id": str(data["policy_id"]) if data.get("policy_id") else None,
        "policy": data.get("policy"),
        "policy_version": data.get("policy_version"),
        "obligations": dict(data.get("obligations") or {}),
        "risk": dict(data.get("risk") or {}),
        "data_classes": list(data.get("data_classes") or []),
        "action_hash": data.get("action_hash"),
        "approval": ApprovalInfo.from_api(approval) if isinstance(approval, Mapping) else None,
        "decision_token": data.get("decision_token"),
        "expires_at": parse_time(data.get("expires_at")),
        "run_id": data.get("run_id"),
        "executed": bool(data.get("executed", False)),
        "result": data.get("result"),
        "result_meta": dict(data.get("result_meta") or {}),
        "error": error,
        "raw": dict(data),
    }


@dataclass(frozen=True)
class ScanResult:
    """The verdict on untrusted content (``POST /api/v1/content/scan``)."""

    verdict: Literal["none", "suspicious", "injection"]
    score: float
    signals: list[dict[str, Any]] = field(default_factory=list)
    data_classes: list[str] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    tainted_run: bool = False
    content: str | None = None
    raw: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @property
    def is_injection(self) -> bool:
        return self.verdict == "injection"

    @classmethod
    def from_api(cls, data: Mapping[str, Any]) -> ScanResult:
        verdict = data.get("verdict")
        return cls(
            verdict=verdict if verdict in ("none", "suspicious", "injection") else "suspicious",
            score=float(data.get("score") or 0.0),
            signals=list(data.get("signals") or []),
            data_classes=list(data.get("data_classes") or []),
            findings=list(data.get("findings") or []),
            tainted_run=bool(data.get("tainted_run")),
            content=data.get("content"),
            raw=dict(data),
        )


@dataclass(frozen=True)
class AgentIdentity:
    """Who the credentials belong to (``GET /api/v1/agent/me``)."""

    agent_id: str
    agent: str
    name: str
    org_id: str
    project: str
    status: str
    roles: list[str] = field(default_factory=list)

    @classmethod
    def from_api(cls, data: Mapping[str, Any]) -> AgentIdentity:
        return cls(
            agent_id=str(data.get("agent_id", "")),
            agent=str(data.get("agent", "")),
            name=str(data.get("name", "")),
            org_id=str(data.get("org_id", "")),
            project=str(data.get("project", "")),
            status=str(data.get("status", "")),
            roles=list(data.get("roles") or []),
        )


@dataclass(frozen=True)
class VerifiedDecision:
    """A decision token that passed every check on the resource side."""

    decision_id: str
    org_id: str
    agent_id: str
    agent: str
    tool: str
    action: str
    resource: str
    action_hash: str
    obligations: dict[str, Any]
    expires_at: datetime | None
    token_id: str
    # False in offline mode: the token was not used up and could be presented again.
    redeemed: bool
