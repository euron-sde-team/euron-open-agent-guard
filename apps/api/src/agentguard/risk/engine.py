"""Risk scoring for one action: a number, a level and the factors behind it.

Risk prioritises; it does not authorize. Policies can condition on it (``risk.level >=
"high"``), reviewers see the factors, and the dashboard sorts by it, but an allowed action
is allowed because a permission or a policy said so, never because its risk was low.

The score starts from the tool's baseline and adds points for the operation, the
resource's sensitivity and environment, the classes of data in the parameters, sending data
outside, a tainted run and the agent's recent history. Organisations add their own rules:
an expression and the points it adds (negative points lower the score). The total is clamped
to 0 to 100 and mapped to a level.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agentguard.policies import expr

TOOL_BASE = {"low": 5, "medium": 20, "high": 40, "critical": 70}
DESTRUCTIVE = ("delete", "drop", "destroy", "purge", "wipe", "truncate", "terminate", "revoke")
MUTATING = (
    "write",
    "update",
    "create",
    "insert",
    "send",
    "transfer",
    "pay",
    "refund",
    "execute",
    "run",
    "deploy",
    "publish",
    "post",
    "modify",
    "grant",
)
SENSITIVITY = {"public": 0, "internal": 3, "confidential": 10, "restricted": 20}
DATA_CLASS = {"pii": 10, "financial": 15, "credentials": 30, "health": 20}


@dataclass(frozen=True, slots=True)
class RiskRule:
    name: str
    condition: list[Any]
    points: int


@dataclass(slots=True)
class Assessment:
    score: int
    level: str
    factors: list[dict[str, Any]] = field(default_factory=list)


def level_for(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def _verb_points(action: str) -> tuple[int, str] | None:
    a = action.lower()
    if any(a == v or a.startswith(v + "_") or a.endswith("_" + v) for v in DESTRUCTIVE):
        return 25, "destructive operation"
    if any(a == v or a.startswith(v + "_") or a.endswith("_" + v) for v in MUTATING):
        return 10, "changes state"
    return None


def assess(data: dict[str, Any], rules: list[RiskRule] | None = None) -> Assessment:
    factors: list[dict[str, Any]] = []

    def add(points: int, factor: str) -> None:
        if points:
            factors.append({"factor": factor, "points": points})

    tool = data.get("tool") or {}
    add(
        TOOL_BASE.get(str(tool.get("risk", "medium")), 30),
        f"tool baseline ({tool.get('risk', 'medium')})",
    )
    verb = _verb_points(str(data.get("action", "")))
    if verb:
        add(*verb)
    resource = data.get("resource") or {}
    if resource.get("registered"):
        sens = str(resource.get("sensitivity", "internal"))
        add(SENSITIVITY.get(sens, 5), f"{sens} resource")
        if resource.get("environment") == "production":
            add(5, "production resource")
    elif (data.get("project") or {}).get("environment") == "production":
        add(5, "production project")
    classes = list((data.get("context") or {}).get("data_classes") or [])
    for cls in classes:
        add(DATA_CLASS.get(cls, 5), f"{cls} data in parameters")
    context = data.get("context") or {}
    if tool.get("external") and (set(classes) - {"pii"} or int(context.get("pii_count", 0)) >= 3):
        add(15, "sends classified data outside")
    run = data.get("run") or {}
    if run.get("tainted"):
        add(10, "run read untrusted content flagged as injection")
    history = (data.get("agent") or {}).get("history") or {}
    open_threats = int(history.get("open_threats", 0))
    if open_threats:
        add(min(30, 15 * open_threats), f"{open_threats} open threat(s) on this agent")
    recent_denies = int(history.get("recent_denies", 0))
    if recent_denies >= 3:
        add(10, f"{recent_denies} denied actions in the last 10 minutes")
    for rule in rules or []:
        try:
            if expr.evaluate(rule.condition, data):
                add(rule.points, rule.name)
        except expr.EvalError:
            continue
    score = max(0, min(100, sum(f["points"] for f in factors)))
    return Assessment(score=score, level=level_for(score), factors=factors)
