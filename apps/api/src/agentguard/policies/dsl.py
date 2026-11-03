"""The policy format: YAML a person writes, compiled into the form the engine evaluates.

The brief's example is valid as written::

    name: production-database-protection
    scope:
      agents: [finance-agent, support-agent]
    resources: [database:production]
    actions: [read, write, delete]
    rules:
      read:   {decision: allow}
      write:  {decision: require_approval}
      delete: {decision: deny}

Rules may also be a list, each with its own ``actions``, ``tools``, ``resources`` and a
``when`` condition (see ``policies.expr``)::

    rules:
      - actions: [refund]
        when: params.amount > 500
        decision: require_approval
        approval: {roles: [finance_lead], count: 2, expires_in: 4h}
      - actions: [export]
        decision: restrict
        obligations: {max_rows: 100, redact_fields: [email, phone]}

Decisions: ``allow``, ``deny``, ``require_approval``, ``restrict`` (allow with obligations
the execution adapter applies) and ``quarantine`` (deny, and quarantine the agent).
Compilation checks everything a mistake could hide in: unknown keys, unknown decisions,
invalid expressions, approvals that nobody could give.
"""

from __future__ import annotations

import re
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from agentguard.policies import expr

DECISIONS = ("allow", "deny", "require_approval", "restrict", "quarantine")
REVIEWER_ROLES = ("reviewer", "security_officer", "org_admin")
MAX_SOURCE_BYTES = 200_000
MAX_RULES = 200
_DURATION = re.compile(r"^(\d+)\s*([smhd])$")
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86_400}


class PolicyError(ValueError):
    """The policy cannot be compiled; the message says where and why."""


def duration_s(value: str | int) -> int:
    if isinstance(value, int):
        return value
    m = _DURATION.match(value.strip())
    if not m:
        raise ValueError(f"{value!r} is not a duration (use 30m, 4h, 2d)")
    return int(m.group(1)) * _UNITS[m.group(2)]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Scope(_Strict):
    # The organisation's slug: a policy naming another organisation never applies here.
    organization: str | None = None
    agents: list[str] = Field(default_factory=list)
    projects: list[str] = Field(default_factory=list)
    roles: list[str] = Field(default_factory=list)
    labels: dict[str, str | int | bool] = Field(default_factory=dict)
    environments: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)


class Stage(_Strict):
    roles: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    count: int = Field(1, ge=1, le=10)

    @field_validator("roles")
    @classmethod
    def _roles(cls, v: list[str]) -> list[str]:
        bad = [r for r in v if r not in REVIEWER_ROLES]
        if bad:
            raise ValueError(f"approver roles are {', '.join(REVIEWER_ROLES)}; got {bad}")
        return v

    @model_validator(mode="after")
    def _someone(self) -> Stage:
        if not self.roles and not self.users:
            self.roles = ["reviewer", "security_officer", "org_admin"]
        return self


class Approval(_Strict):
    # Shorthand for one stage.
    roles: list[str] = Field(default_factory=list)

    @field_validator("roles")
    @classmethod
    def _roles(cls, v: list[str]) -> list[str]:
        return Stage._roles(v)

    users: list[str] = Field(default_factory=list)
    count: int = Field(1, ge=1, le=10)
    stages: list[Stage] = Field(default_factory=list)
    expires_in: str | int = "24h"
    # agentguard: AgentGuard runs the action once approved (http, mcp, sandbox tools).
    # agent: the agent retries with the approval and runs it itself (function tools).
    execute: Literal["agentguard", "agent", "auto"] = "auto"
    # The person the run acts for may not approve their own agent's request.
    forbid_requester: bool = True

    @field_validator("expires_in")
    @classmethod
    def _expiry(cls, v: str | int) -> str | int:
        seconds = duration_s(v)
        if not 60 <= seconds <= 30 * 86_400:
            raise ValueError("expires_in must be between 1 minute and 30 days")
        return v

    def compiled(self) -> dict[str, Any]:
        stages = self.stages or [Stage(roles=self.roles, users=self.users, count=self.count)]
        return {
            "stages": [s.model_dump() for s in stages],
            "expires_in_s": duration_s(self.expires_in),
            "execute": self.execute,
            "forbid_requester": self.forbid_requester,
        }


class Obligations(_Strict):
    # Rows a data tool may return (the adapter truncates and says so).
    max_rows: int | None = Field(None, ge=0, le=1_000_000)
    # Parameter or result fields replaced with [REDACTED].
    redact_fields: list[str] = Field(default_factory=list)
    # Redact personal data and credentials found in the tool's response.
    redact_output: bool = False
    # Mark the response as untrusted data for the model (spotlighting).
    wrap_untrusted: bool = False
    # Cap on the tool's timeout and response size.
    timeout_s: float | None = Field(None, gt=0, le=600)
    max_response_bytes: int | None = Field(None, ge=1, le=50_000_000)
    # Sandbox runs: no network at all.
    no_network: bool = False
    # Only these parameters may be sent (others are dropped).
    allow_params: list[str] = Field(default_factory=list)


class Rule(_Strict):
    actions: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=list)
    when: str = ""
    decision: Literal["allow", "deny", "require_approval", "restrict", "quarantine"]
    reason: str = Field("", max_length=500)
    obligations: Obligations | None = None
    approval: Approval | None = None

    @model_validator(mode="after")
    def _coherent(self) -> Rule:
        if self.decision == "restrict" and self.obligations is None:
            raise ValueError("restrict needs obligations (what to restrict)")
        if self.decision == "require_approval" and self.approval is None:
            self.approval = Approval()
        if self.approval is not None and self.decision != "require_approval":
            raise ValueError("approval only applies to decision require_approval")
        return self


class PolicyDoc(_Strict):
    name: str = Field(..., min_length=2, max_length=120, pattern=r"^[a-z0-9][a-z0-9_.-]*$")
    description: str = Field("", max_length=1000)
    scope: Scope = Field(default_factory=Scope)
    tools: list[str] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=list)
    actions: list[str] = Field(default_factory=list)
    when: str = ""
    rules: list[Rule] | dict[str, Rule | dict[str, Any]]

    @field_validator("rules", mode="before")
    @classmethod
    def _rules_shape(cls, v: Any) -> Any:
        if isinstance(v, dict):
            # {action: {decision: ...}} : the brief's form. "*" means every action.
            return [{**(rule or {}), "actions": [action]} for action, rule in v.items()]
        return v


def _check_expr(source: str, where: str) -> list[Any] | None:
    if not source:
        return None
    try:
        return expr.parse(source)
    except expr.ExprError as exc:
        raise PolicyError(f"{where}: {exc}") from exc


# Messages Pydantic adds for the union branch the document did not use (``rules`` is a list
# or a map keyed by action): noise next to the real error in the branch that was used.
_WRONG_BRANCH = ("Input should be a valid dictionary", "Input should be a valid list")


def _path(loc: tuple[int | str, ...]) -> str:
    """``rules.2.decision`` style locations as ``rules[2].decision``, union tags dropped."""
    out = ""
    for part in loc:
        if isinstance(part, int):
            out += f"[{part}]"
        elif "[" in part or "(" in part:
            continue  # a union branch tag such as list[function-after[_coherent(), Rule]]
        else:
            out += f".{part}" if out else part
    return out


def _errors(exc: ValidationError) -> str:
    errors = exc.errors()
    real = [e for e in errors if not str(e["msg"]).startswith(_WRONG_BRANCH)]
    parts: list[str] = []
    for err in (real or errors)[:8]:
        msg = str(err["msg"]).removeprefix("Value error, ")
        line = f"{_path(err['loc'])}: {msg}" if err["loc"] else msg
        if line not in parts:
            parts.append(line)
    return "; ".join(parts)


def _compile_rules(doc: PolicyDoc, rules: list[Any]) -> list[dict[str, Any]]:
    compiled_rules: list[dict[str, Any]] = []
    for i, raw in enumerate(rules):
        rule = raw if isinstance(raw, Rule) else Rule.model_validate(raw)
        actions = rule.actions or doc.actions or ["*"]
        if doc.actions and "*" not in doc.actions:
            outside = [a for a in actions if a != "*" and a not in doc.actions]
            if outside:
                raise PolicyError(
                    f"rules[{i}]: actions {outside} are not in the policy's actions {doc.actions}"
                )
            if actions == ["*"]:
                actions = list(doc.actions)
        compiled_rules.append(
            {
                "index": i,
                "actions": actions,
                "tools": rule.tools,
                "resources": rule.resources,
                "when": _check_expr(rule.when, f"rules[{i}].when"),
                "when_source": rule.when,
                "decision": rule.decision,
                "reason": rule.reason,
                "obligations": rule.obligations.model_dump(exclude_defaults=True)
                if rule.obligations
                else {},
                "approval": rule.approval.compiled() if rule.approval else None,
            }
        )
    return compiled_rules


def compile_policy(source: str) -> dict[str, Any]:
    """YAML source to the compiled form. Raises :class:`PolicyError` with a readable message."""
    if len(source.encode()) > MAX_SOURCE_BYTES:
        raise PolicyError("Policies are limited to 200 KB")
    try:
        data = yaml.safe_load(source)
    except yaml.YAMLError as exc:
        raise PolicyError(f"Not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyError("A policy is a YAML mapping with at least name and rules")
    try:
        doc = PolicyDoc.model_validate(data)
    except ValidationError as exc:
        raise PolicyError(_errors(exc)) from exc
    rules = doc.rules if isinstance(doc.rules, list) else []
    if not rules:
        raise PolicyError("rules: a policy needs at least one rule")
    if len(rules) > MAX_RULES:
        raise PolicyError(f"rules: at most {MAX_RULES} rules per policy")
    try:
        compiled_rules = _compile_rules(doc, rules)
    except ValidationError as exc:
        raise PolicyError(_errors(exc)) from exc
    return {
        "name": doc.name,
        "description": doc.description,
        "scope": doc.scope.model_dump(),
        "tools": doc.tools,
        "resources": doc.resources,
        "actions": doc.actions,
        "when": _check_expr(doc.when, "when"),
        "when_source": doc.when,
        "rules": compiled_rules,
    }


def policy_name(source: str) -> str:
    """The name in a source document, for errors that happen before full compilation."""
    try:
        data = yaml.safe_load(source)
    except yaml.YAMLError:
        return ""
    return str(data.get("name", "")) if isinstance(data, dict) else ""
