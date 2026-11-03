"""The policy language, compiler and engine (AC3, AC15), including property tests."""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from agentguard.policies import engine, expr
from agentguard.policies.dsl import PolicyError, compile_policy

DATA: dict[str, Any] = {
    "agent": {
        "slug": "finance-agent",
        "project": "finance",
        "roles": ["finance"],
        "labels": {"team": "finance", "tier": 1},
        "framework": "crewai",
    },
    "org": {"slug": "acme"},
    "project": {"slug": "finance", "environment": "production"},
    "tool": {"name": "payments.refund", "risk": "high", "external": False},
    "action": "refund",
    "resource": {
        "key": "customer:42",
        "sensitivity": "confidential",
        "registered": True,
        "owned": True,
    },
    "params": {"amount": 450, "currency": "EUR", "to": "bob@corp.example", "tags": ["vip"]},
    "context": {"data_classes": ["pii"], "pii_count": 1},
    "run": {"tainted": False, "calls": 3},
    "risk": {"level": "high", "score": 60},
    "time": {"hour": 14, "weekday": "tue"},
}


def ev(source: str, data: dict[str, Any] | None = None) -> bool:
    return expr.evaluate(expr.parse(source), data or DATA)


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("params.amount > 200", True),
        ("params.amount > 200 and params.amount <= 1000", True),
        ('risk.level >= "high"', True),
        ('risk.level >= "critical"', False),
        ('resource.sensitivity >= "internal"', True),
        ('params.currency in ["EUR", "USD"]', True),
        ('params.currency not in ["EUR"]', False),
        ('context.data_classes contains "pii"', True),
        ("not run.tainted", True),
        ('params.to matches "[^@]+@corp\\\\.example"', True),
        ('params.to startswith "bob" and params.to endswith ".example"', True),
        ('time.weekday in ["sat", "sun"] or time.hour < 8', False),
        ("agent.labels.tier == 1", True),
        ("agent.labels.missing", False),
        ("params.nothing == null", True),
        ("len(params.tags) == 1", True),
        ('lower(params.currency) == "eur"', True),
        ('any_of(context.data_classes, ["pii", "financial"])', True),
        ("(params.amount > 1000 or tool.external) and true", False),
        ('org.slug == "acme"', True),
    ],
)
def test_expressions(source: str, expected: bool) -> None:
    assert ev(source) is expected


@pytest.mark.parametrize(
    "source",
    [
        "",
        "params.amount >",
        "__import__('os')",
        "foo.bar == 1",
        'params.x matches "("',
        "a" * 3000,
        "(" * 40 + "true" + ")" * 40,
        "x() == 1",
        "params.a == [params.b]",
    ],
)
def test_invalid_expressions_are_refused_with_a_message(source: str) -> None:
    with pytest.raises(expr.ExprError):
        expr.parse(source)


@pytest.mark.parametrize(
    "source",
    [
        "params.amount > params.tags",
        "params.tags < 3",
        'params.amount startswith "4"',
        "len(params.amount) > 1",
        "true < false",
    ],
)
def test_type_errors_raise_eval_errors(source: str) -> None:
    with pytest.raises(expr.EvalError):
        ev(source)


def test_paths_are_reported() -> None:
    assert expr.paths(expr.parse('params.amount > 1 and risk.level == "high"')) == {
        "params.amount",
        "risk.level",
    }


BRIEF = """name: production-database-protection
scope:
  organization: acme
  agents: [finance-agent, support-agent]
resources: [database:production]
actions: [read, write, delete]
rules:
  read: {decision: allow}
  write: {decision: require_approval}
  delete: {decision: deny}
"""


def _active(*sources: str) -> list[engine.ActivePolicy]:
    out = []
    for i, source in enumerate(sources):
        compiled = compile_policy(source)
        out.append(engine.ActivePolicy(str(i), compiled["name"], 1, compiled))
    return out


def _with(**changes: Any) -> dict[str, Any]:
    data = {**DATA}
    for key, value in changes.items():
        data[key] = value
    return data


def test_the_brief_policy_compiles_and_decides() -> None:
    policies = _active(BRIEF)
    res = {"key": "database:production"}
    for action, decision in (("read", "allow"), ("write", "require_approval"), ("delete", "deny")):
        out = engine.evaluate(policies, [], _with(action=action, resource=res))
        assert out.decision == decision
    assert engine.evaluate(policies, [], _with(action="truncate", resource=res)).decision == "deny"
    assert (
        engine.evaluate(
            policies, [], _with(action="read", resource=res, org={"slug": "other"})
        ).reason_code
        == "no_permission"
    )
    approval = engine.evaluate(policies, [], _with(action="write", resource=res)).approval
    assert approval is not None and approval["stages"][0]["roles"] == [
        "reviewer",
        "security_officer",
        "org_admin",
    ]


@pytest.mark.parametrize(
    ("source", "message"),
    [
        ("name: xx\nrules: []\n", "at least one rule"),
        ("name: Bad Name\nrules:\n  - decision: allow\n", "name"),
        ("name: xx\nrules:\n  - decision: maybe\n", "decision"),
        ("name: xx\nrules:\n  - decision: restrict\n", "obligations"),
        (
            "name: xx\nrules:\n  - decision: allow\n    approval: {roles: [reviewer]}\n",
            "approval only applies",
        ),
        ("name: xx\nrules:\n  - decision: deny\n    when: params.a >\n", r"rules\[0\]\.when"),
        ("name: xx\nunknown: 1\nrules:\n  - decision: deny\n", "unknown"),
        (
            "name: xx\nactions: [read]\nrules:\n  - actions: [write]\n    decision: deny\n",
            "not in the policy's actions",
        ),
        (
            "name: xx\nrules:\n  - decision: require_approval\n    approval: {roles: [auditor]}\n",
            "approver roles",
        ),
        (
            "name: xx\nrules:\n  - decision: require_approval\n    approval: {expires_in: 1s}\n",
            "expires_in",
        ),
        ("- just a list", "mapping"),
        ("name: [unclosed", "YAML"),
    ],
)
def test_policy_errors_are_readable(source: str, message: str) -> None:
    with pytest.raises(PolicyError, match=message):
        compile_policy(source)


DENY = "name: deny-writes\nrules:\n  - actions: [write]\n    decision: deny\n    reason: frozen\n"
ALLOW = "name: allow-all\nrules:\n  - decision: allow\n"


def test_deny_beats_allow_regardless_of_order() -> None:
    for order in ((DENY, ALLOW), (ALLOW, DENY)):
        out = engine.evaluate(_active(*order), [], _with(action="write"))
        assert out.decision == "deny" and out.reason == "frozen"
    assert engine.evaluate(_active(DENY, ALLOW), [], _with(action="read")).decision == "allow"


def test_permissions_grant_only_when_no_rule_matches() -> None:
    grant = engine.Grant(
        role="finance", tool="payments.*", actions=("refund",), resource="customer:*"
    )
    out = engine.evaluate([], [grant], DATA)
    assert (
        out.decision == "allow" and out.reason_code == "permission" and out.granted_by == "finance"
    )
    assert engine.evaluate([], [grant], _with(action="delete")).decision == "deny"
    assert engine.evaluate([], [grant], _with(resource={"key": "invoice:1"})).decision == "deny"
    conditional = engine.Grant(
        role="small",
        tool="payments.refund",
        actions=("refund",),
        resource="*",
        condition=expr.parse("params.amount < 100"),
    )
    assert engine.evaluate([], [conditional], DATA).decision == "deny"
    assert engine.evaluate([], [], DATA, default="allow").reason_code == "default_allow"


def test_a_broken_condition_can_deny_but_never_grant() -> None:
    broken_allow = "name: aa\nrules:\n  - decision: allow\n    when: params.amount > params.tags\n"
    broken_deny = "name: dd\nrules:\n  - decision: deny\n    when: params.amount > params.tags\n"
    assert engine.evaluate(_active(broken_allow), [], DATA).decision == "deny"
    out = engine.evaluate(_active(broken_deny), [], DATA)
    assert out.decision == "deny" and out.matched[0].error


def test_restrict_merges_the_most_restrictive_obligations() -> None:
    a = "name: aa\nrules:\n  - decision: restrict\n    obligations: {max_rows: 50, redact_fields: [email], allow_params: [a, b]}\n"
    b = "name: bb\nrules:\n  - decision: restrict\n    obligations: {max_rows: 10, redact_fields: [phone], redact_output: true, allow_params: [b, c]}\n"
    out = engine.evaluate(_active(a, b), [], DATA)
    assert out.decision == "restrict"
    assert out.obligations == {
        "max_rows": 10,
        "redact_fields": ["email", "phone"],
        "redact_output": True,
        "allow_params": ["b"],
    }


def test_the_strictest_approval_wins_and_specific_rules_explain() -> None:
    one = "name: zz-one\ntools: [payments.refund]\nrules:\n  - decision: require_approval\n    reason: specific\n"
    two = "name: aa-two\nrules:\n  - decision: require_approval\n    reason: generic\n    approval: {count: 2, roles: [reviewer]}\n"
    out = engine.evaluate(_active(one, two), [], DATA)
    assert out.reason == "specific"
    assert out.approval is not None and out.approval["stages"][0]["count"] == 2


def test_scope_by_agent_role_label_project_environment_and_framework() -> None:
    for scope, applies in (
        ("agents: [finance-*]", True),
        ("agents: [support-agent]", False),
        ("roles: [finance]", True),
        ("labels: {team: finance}", True),
        ("labels: {team: support}", False),
        ("projects: [finance]", True),
        ("environments: [staging]", False),
        ("frameworks: [crewai]", True),
    ):
        source = f"name: ss\nscope:\n  {scope}\nrules:\n  - decision: deny\n"
        assert (engine.evaluate(_active(source), [], DATA).decision == "deny") is True
        assert bool(engine.evaluate(_active(source), [], DATA).matched) is applies


def test_tool_visibility_ignores_org_wide_guards() -> None:
    from agentguard.policies.builtin import BUILTIN

    builtins = _active(*BUILTIN)
    assert not engine.could_allow(builtins, [], DATA, "files.read_file")
    assert engine.could_allow(
        builtins, [engine.Grant("r", "files.*", (), "*")], DATA, "files.read_file"
    )
    scoped = _active(
        "name: ss\nscope:\n  agents: [finance-agent]\nrules:\n  - decision: require_approval\n"
    )
    assert engine.could_allow(scoped, [], DATA, "anything")


def test_builtin_policies_compile_and_guard() -> None:
    from agentguard.policies.builtin import BUILTIN

    policies = _active(*BUILTIN)
    tainted = _with(run={"tainted": True}, risk={"level": "high", "score": 70})
    assert engine.evaluate(policies, [], tainted).decision == "require_approval"
    other_project = _with(
        resource={"key": "db:x", "registered": True, "project": "hr", "owned": False}
    )
    assert engine.evaluate(policies, [], other_project).reason_code == "policy_deny"
    creds = _with(
        tool={"name": "email.send", "external": True},
        context={"data_classes": ["credentials"], "pii_count": 0},
    )
    assert engine.evaluate(policies, [], creds).decision == "deny"
    bulk = _with(
        tool={"name": "email.send", "external": True},
        context={"data_classes": ["pii"], "pii_count": 5},
    )
    assert engine.evaluate(policies, [], bulk).decision == "require_approval"
    one_address = _with(
        tool={"name": "email.send", "external": True},
        context={"data_classes": ["pii"], "pii_count": 1},
    )
    assert (
        engine.evaluate(policies, [engine.Grant("m", "*", (), "*")], one_address).decision
        == "allow"
    )


DECISIONS = st.sampled_from(["allow", "deny", "require_approval", "restrict", "quarantine"])


def _rule(decision: str, action: str) -> str:
    extra = "    obligations: {max_rows: 1}\n" if decision == "restrict" else ""
    return f"  - actions: [{action}]\n    decision: {decision}\n{extra}"


@settings(max_examples=150, deadline=None)
@given(
    st.lists(
        st.tuples(DECISIONS, st.sampled_from(["refund", "read", '"*"'])), min_size=1, max_size=8
    ),
    st.randoms(),
)
def test_property_strongest_decision_wins_and_order_does_not_matter(
    rules: list[tuple[str, str]], rnd: Any
) -> None:
    sources = [f"name: pp{i}\nrules:\n{_rule(d, a)}" for i, (d, a) in enumerate(rules)]
    policies = _active(*sources)
    shuffled = list(policies)
    rnd.shuffle(shuffled)
    first = engine.evaluate(policies, [], DATA)
    second = engine.evaluate(shuffled, [], DATA)
    assert (first.decision, first.reason, first.reason_code) == (
        second.decision,
        second.reason,
        second.reason_code,
    )
    applicable = [d for d, a in rules if a in ("refund", '"*"')]
    if applicable:
        assert first.decision == max(applicable, key=lambda d: engine.STRENGTH[d])
        if "deny" in applicable or "quarantine" in applicable:
            assert first.decision in ("deny", "quarantine")
    else:
        assert first.decision == "deny" and first.reason_code == "no_permission"


@settings(max_examples=100, deadline=None)
@given(
    st.integers(min_value=-(10**6), max_value=10**6),
    st.sampled_from(["low", "medium", "high", "critical"]),
)
def test_property_evaluation_is_a_pure_function(amount: int, level: str) -> None:
    data = _with(params={**DATA["params"], "amount": amount}, risk={"level": level, "score": 1})
    node = expr.parse('params.amount > 500 or risk.level >= "high"')
    assert (
        expr.evaluate(node, data)
        == expr.evaluate(node, data)
        == (amount > 500 or level in ("high", "critical"))
    )
