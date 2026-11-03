"""The policy engine: deterministic, explainable, deny-overrides.

Given the evaluation input of one action and the active policies, every rule of every
policy is tested; each rule that matches contributes its decision. The strongest decision
wins, in this fixed order:

    quarantine > deny > require_approval > restrict > allow

so an explicit deny anywhere beats every allow, regardless of which policy came first,
when it was written or how many allows there are. Ties between rules of the same strength
are broken by policy name and rule index, so the same input and the same policy versions
always give the same decision and the same explanation.

When no rule matches, permissions decide: an action granted by one of the agent's roles is
allowed, anything else gets the organisation's default (deny in enforce mode).

A condition that cannot be evaluated (a type error) makes its rule match only when the rule
denies or quarantines: an error can add caution, never grant.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Any

from agentguard.policies import expr

STRENGTH = {"allow": 0, "restrict": 1, "require_approval": 2, "deny": 3, "quarantine": 4}


@dataclass(frozen=True, slots=True)
class ActivePolicy:
    id: str
    name: str
    version: int
    compiled: dict[str, Any]


@dataclass(frozen=True, slots=True)
class Grant:
    """A permission an agent holds through one of its roles."""

    role: str
    tool: str
    actions: tuple[str, ...]
    resource: str
    condition: list[Any] | None = None


@dataclass(slots=True)
class Match:
    policy_id: str
    policy: str
    version: int
    rule: int
    decision: str
    reason: str
    obligations: dict[str, Any]
    approval: dict[str, Any] | None
    error: str | None = None
    specificity: int = 0

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "policy_id": self.policy_id,
            "policy": self.policy,
            "version": self.version,
            "rule": self.rule,
            "decision": self.decision,
            "reason": self.reason,
        }
        if self.error:
            out["error"] = self.error
        return out


@dataclass(slots=True)
class Outcome:
    decision: str
    reason_code: str
    reason: str
    deciding: Match | None = None
    matched: list[Match] = field(default_factory=list)
    obligations: dict[str, Any] = field(default_factory=dict)
    approval: dict[str, Any] | None = None
    granted_by: str | None = None


def glob(patterns: list[str] | tuple[str, ...], value: str) -> bool:
    return any(p == "*" or fnmatch.fnmatchcase(value, p) for p in patterns)


def _scope_matches(scope: dict[str, Any], data: dict[str, Any]) -> bool:
    agent = data.get("agent") or {}
    if scope.get("organization") and scope["organization"] != (data.get("org") or {}).get("slug"):
        return False
    if scope.get("agents") and not glob(scope["agents"], str(agent.get("slug", ""))):
        return False
    if scope.get("projects") and not glob(scope["projects"], str(agent.get("project", ""))):
        return False
    if scope.get("roles") and not set(scope["roles"]) & set(agent.get("roles") or []):
        return False
    labels = agent.get("labels") or {}
    for key, value in (scope.get("labels") or {}).items():
        if labels.get(key) != value:
            return False
    if (
        scope.get("environments")
        and (data.get("project") or {}).get("environment") not in scope["environments"]
    ):
        return False
    return not (scope.get("frameworks") and agent.get("framework") not in scope["frameworks"])


def _when(node: list[Any] | None, data: dict[str, Any]) -> tuple[bool, str | None]:
    if node is None:
        return True, None
    try:
        return expr.evaluate(node, data), None
    except expr.EvalError as exc:
        return False, str(exc)


def _rule_matches(
    policy: dict[str, Any], rule: dict[str, Any], data: dict[str, Any]
) -> tuple[bool, str | None]:
    action = str(data.get("action", ""))
    tool = str((data.get("tool") or {}).get("name", ""))
    resource = str((data.get("resource") or {}).get("key", ""))
    if not glob(rule["actions"], action):
        return False, None
    tools = rule["tools"] or policy["tools"]
    if tools and not glob(tools, tool):
        return False, None
    resources = rule["resources"] or policy["resources"]
    if resources and not glob(resources, resource):
        return False, None
    ok, error = _when(policy.get("when"), data)
    if error:
        return rule["decision"] in ("deny", "quarantine"), error
    if not ok:
        return False, None
    ok, error = _when(rule.get("when"), data)
    if error:
        return rule["decision"] in ("deny", "quarantine"), error
    return ok, None


def _specificity(policy: dict[str, Any], rule: dict[str, Any]) -> int:
    """How narrowly a rule targets: named tools and resources, a scope, a condition."""
    scope = policy.get("scope") or {}
    return (
        (4 if rule["tools"] or policy["tools"] else 0)
        + (3 if rule["resources"] or policy["resources"] else 0)
        + (
            2
            if any(scope.get(k) for k in ("agents", "projects", "roles", "labels", "frameworks"))
            else 0
        )
        + (1 if rule.get("when") or policy.get("when") else 0)
        + (1 if rule["actions"] != ["*"] else 0)
    )


def _merge_obligations(matches: list[Match]) -> dict[str, Any]:
    """The most restrictive combination of every restrict rule that matched."""
    merged: dict[str, Any] = {}
    for m in matches:
        for key, value in m.obligations.items():
            if key in ("max_rows", "timeout_s", "max_response_bytes"):
                merged[key] = value if key not in merged else min(merged[key], value)
            elif key in ("redact_fields",):
                merged[key] = sorted(set(merged.get(key, [])) | set(value))
            elif key == "allow_params":
                merged[key] = (
                    sorted(set(merged[key]) & set(value)) if key in merged else sorted(value)
                )
            elif isinstance(value, bool):
                merged[key] = merged.get(key, False) or value
            else:
                merged[key] = value
    return merged


def _strictest_approval(matches: list[Match]) -> dict[str, Any] | None:
    best: dict[str, Any] | None = None
    for m in matches:
        if m.approval is None:
            continue
        if best is None:
            best = m.approval
            continue
        best_people = sum(s["count"] for s in best["stages"])
        people = sum(s["count"] for s in m.approval["stages"])
        if (len(m.approval["stages"]), people) > (len(best["stages"]), best_people):
            best = m.approval
        elif (len(m.approval["stages"]), people) == (len(best["stages"]), best_people):
            best = {**best, "expires_in_s": min(best["expires_in_s"], m.approval["expires_in_s"])}
    return best


def granted(grants: list[Grant], data: dict[str, Any]) -> Grant | None:
    """The first permission that grants this action, in a stable order."""
    action = str(data.get("action", ""))
    tool = str((data.get("tool") or {}).get("name", ""))
    resource = str((data.get("resource") or {}).get("key", ""))
    for g in sorted(grants, key=lambda g: (g.role, g.tool, g.resource, g.actions)):
        if not glob([g.tool], tool):
            continue
        if g.actions and not glob(list(g.actions), action):
            continue
        # A grant scoped to resources only covers actions on a matching resource.
        if g.resource and g.resource != "*" and (not resource or not glob([g.resource], resource)):
            continue
        if g.condition is not None:
            ok, error = _when(g.condition, data)
            if error or not ok:
                continue
        return g
    return None


def evaluate(
    policies: list[ActivePolicy],
    grants: list[Grant],
    data: dict[str, Any],
    *,
    default: str = "deny",
) -> Outcome:
    matches: list[Match] = []
    for policy in sorted(policies, key=lambda p: p.name):
        compiled = policy.compiled
        if not _scope_matches(compiled.get("scope") or {}, data):
            continue
        for rule in compiled["rules"]:
            ok, error = _rule_matches(compiled, rule, data)
            if not ok:
                continue
            matches.append(
                Match(
                    policy_id=policy.id,
                    policy=policy.name,
                    version=policy.version,
                    rule=rule["index"],
                    decision=rule["decision"],
                    reason=rule["reason"] or f"{policy.name}: {rule['decision'].replace('_', ' ')}",
                    obligations=rule.get("obligations") or {},
                    approval=rule.get("approval"),
                    error=error,
                    specificity=_specificity(compiled, rule),
                )
            )
    if matches:
        top = max(STRENGTH[m.decision] for m in matches)
        # Among rules of the winning strength, the most specific one explains the decision
        # (a rule naming this tool says more than an organisation-wide guard); ties keep
        # the policy name and rule order, so the choice is still deterministic.
        winners = sorted(
            (m for m in matches if STRENGTH[m.decision] == top),
            key=lambda m: (-m.specificity, m.policy, m.rule),
        )
        deciding = winners[0]
        decision = deciding.decision
        outcome = Outcome(
            decision=decision,
            reason_code={
                "allow": "policy_allow",
                "restrict": "policy_restrict",
                "require_approval": "approval_required",
                "deny": "policy_deny",
                "quarantine": "policy_quarantine",
            }[decision],
            reason=deciding.reason,
            deciding=deciding,
            matched=matches,
        )
        if decision == "restrict":
            outcome.obligations = _merge_obligations(winners)
        if decision == "require_approval":
            outcome.approval = _strictest_approval(winners)
        return outcome
    grant = granted(grants, data)
    if grant is not None:
        return Outcome(
            decision="allow",
            reason_code="permission",
            reason=f"Granted by role {grant.role}",
            granted_by=grant.role,
        )
    if default == "allow":
        return Outcome(decision="allow", reason_code="default_allow", reason="No policy matched")
    return Outcome(
        decision="deny",
        reason_code="no_permission",
        reason="No permission or policy allows this action",
    )


def stronger(a: str, b: str) -> str:
    return a if STRENGTH[a] >= STRENGTH[b] else b


def could_allow(
    policies: list[ActivePolicy],
    grants: list[Grant],
    data: dict[str, Any],
    tool_name: str,
    action: str = "call",
) -> bool:
    """Whether any permission or policy rule could ever allow this tool for this agent.

    Optimistic: conditions and resources are ignored, so a tool that is allowed only for
    some parameters is still listed. Used to hide tools an agent can never use (MCP
    ``tools/list``); every call is still decided in full.
    """
    for g in grants:
        if glob([g.tool], tool_name) and (not g.actions or glob(list(g.actions), action)):
            return True
    for policy in policies:
        compiled = policy.compiled
        scope = compiled.get("scope") or {}
        if not _scope_matches(scope, data):
            continue
        scoped = any(scope.get(k) for k in ("agents", "projects", "roles", "labels", "frameworks"))
        for rule in compiled["rules"]:
            if rule["decision"] not in ("allow", "restrict", "require_approval"):
                continue
            tools = rule["tools"] or compiled["tools"]
            if tools and not glob(tools, tool_name):
                continue
            # Organisation-wide guard rules (the built-in policies) add caution to every
            # action; they are not grants, so they do not make a tool visible.
            if not tools and not scoped:
                continue
            if glob(rule["actions"], action):
                return True
    return False
