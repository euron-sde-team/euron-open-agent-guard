"""The decision API's request and response shapes (the contract every SDK implements)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

DecisionLiteral = Literal["allow", "deny", "require_approval", "restrict", "quarantine"]
MAX_PARAMETER_DEPTH = 32
_INT_LIMIT = 2**63


def check_parameters(value: Any, depth: int = 0) -> None:
    """Parameters must hash canonically: bounded nesting, 64-bit integers."""
    if depth > MAX_PARAMETER_DEPTH:
        raise ValueError(f"parameters may nest at most {MAX_PARAMETER_DEPTH} levels")
    if isinstance(value, bool):
        return
    if isinstance(value, int) and not -_INT_LIMIT <= value < _INT_LIMIT:
        raise ValueError("integers must fit in 64 bits (send larger numbers as strings)")
    if isinstance(value, dict):
        for item in value.values():
            check_parameters(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            check_parameters(item, depth + 1)


class AuthorizeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool: str = Field(..., min_length=1, max_length=200)
    action: str = Field("call", min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.:-]+$")
    # The resource key ("customer:1024"). Omitted: built from the tool's resource template.
    resource: str | None = Field(None, max_length=300)
    parameters: dict[str, Any] = Field(default_factory=dict)
    # The agent's own name for this execution (a task or thread id); limits and taint use it.
    run_id: str | None = Field(None, max_length=128, pattern=r"^[A-Za-z0-9_.:@/-]+$")
    # The person the agent acts for, as the calling application states it (context only).
    on_behalf_of: str | None = Field(None, max_length=320)
    # Free context for policies (context.<key>): channel, ticket id, environment...
    context: dict[str, Any] = Field(default_factory=dict)
    # An approval this request redeems (optional: an approved request with the same action
    # hash is found automatically).
    approval_id: uuid.UUID | None = None
    # Ask for a decision token even for tools AgentGuard does not run itself.
    want_token: bool = False

    @field_validator("parameters", "context")
    @classmethod
    def _hashable(cls, v: dict[str, Any]) -> dict[str, Any]:
        check_parameters(v)
        return v


class Approval(BaseModel):
    id: uuid.UUID
    status: str
    expires_at: datetime
    url: str
    required: list[dict[str, Any]] = Field(default_factory=list)
    comment: str | None = None


class AuthorizeResponse(BaseModel):
    decision_id: uuid.UUID
    decision: DecisionLiteral
    allowed: bool
    # What enforce mode would have decided (differs from decision only in audit mode).
    would_be: DecisionLiteral
    mode: Literal["enforce", "audit"]
    reason_code: str
    reason: str
    reasons: list[str] = Field(default_factory=list)
    policy_id: uuid.UUID | None = None
    policy: str | None = None
    policy_version: int | None = None
    obligations: dict[str, Any] = Field(default_factory=dict)
    risk: dict[str, Any] = Field(default_factory=dict)
    data_classes: list[str] = Field(default_factory=list)
    action_hash: str
    approval: Approval | None = None
    # A single-use, signed token proving this exact action was allowed (function tools).
    decision_token: str | None = None
    expires_at: datetime | None = None
    run_id: str | None = None


class ExecuteResponse(AuthorizeResponse):
    executed: bool = False
    # The tool's result, after obligations (redaction, truncation, spotlighting).
    result: Any = None
    result_meta: dict[str, Any] = Field(default_factory=dict)


class EvaluateRequest(BaseModel):
    """A dry run for the policy builder: decide for any agent without recording anything."""

    model_config = ConfigDict(extra="forbid")
    agent: str = Field(..., min_length=1, max_length=64)
    request: AuthorizeRequest
    # Evaluate a draft policy too (YAML), as if it were active.
    draft: str | None = Field(None, max_length=200_000)


class EvaluateResponse(BaseModel):
    decision: DecisionLiteral
    reason_code: str
    reason: str
    matched: list[dict[str, Any]]
    obligations: dict[str, Any]
    risk: dict[str, Any]
    input: dict[str, Any]


class RedeemRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str = Field(..., min_length=20, max_length=8000)
    # The verifier's own hash of the action it is about to run; must match the token's.
    action_hash: str | None = Field(None, min_length=64, max_length=64)


class RedeemResponse(BaseModel):
    valid: bool
    reason: str
    decision_id: uuid.UUID | None = None
    agent: str | None = None
    tool: str | None = None
    action: str | None = None
    resource: str | None = None
    obligations: dict[str, Any] = Field(default_factory=dict)


class ScanRequest(BaseModel):
    """Untrusted content an agent read (a web page, an email, another agent's message)."""

    model_config = ConfigDict(extra="forbid")
    content: str = Field(..., max_length=500_000)
    source: str = Field("unknown", max_length=200)
    run_id: str | None = Field(None, max_length=128, pattern=r"^[A-Za-z0-9_.:@/-]+$")
    # Return the content wrapped as untrusted data, with hidden characters removed.
    spotlight: bool = False


class ScanResponse(BaseModel):
    verdict: Literal["none", "suspicious", "injection"]
    score: float
    signals: list[dict[str, Any]]
    data_classes: list[str]
    findings: list[dict[str, Any]]
    tainted_run: bool
    classifier: dict[str, Any] | None = None
    content: str | None = None


class DecisionOut(BaseModel):
    id: uuid.UUID
    at: datetime
    agent_id: uuid.UUID | None
    agent: str | None = None
    run_id: uuid.UUID | None
    source: str
    tool: str
    action: str
    resource: str
    decision: str
    would_be: str
    mode: str
    reason_code: str
    reasons: list[Any]
    policy_id: uuid.UUID | None
    policy_name: str | None
    policy_version: int | None
    risk_level: str
    risk_score: int
    data_classes: list[str]
    obligations: dict[str, Any]
    approval_id: uuid.UUID | None
    latency_ms: float
    execution: str
    on_behalf_of: str | None


class DecisionDetail(DecisionOut):
    params: dict[str, Any]
    matched: list[Any]
    risk_factors: list[Any]
    execution_meta: dict[str, Any]
    action_hash: str


class RunOut(BaseModel):
    id: uuid.UUID
    agent_id: uuid.UUID
    run_key: str
    started_at: datetime
    last_at: datetime
    ended_at: datetime | None
    tool_calls: int
    denied: int
    data_bytes: int
    tainted_at: datetime | None
    taint: dict[str, Any]
    on_behalf_of: str | None
