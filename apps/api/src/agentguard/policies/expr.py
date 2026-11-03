"""The condition language of policies and permissions.

A small, side-effect-free expression language, parsed by hand (never ``eval``) into a tree
of lists that is stored in the compiled policy and evaluated per decision::

    risk.level >= "high" and tool.external
    params.amount > 500 or resource.sensitivity in ["confidential", "restricted"]
    context.data_classes contains "pii" and not agent.labels.pii_cleared
    time.hour < 8 or time.weekday in ["sat", "sun"]
    params.to matches ".*@corp\\.example"

Values: strings ('...' or "..."), numbers, ``true``, ``false``, ``null`` and lists.
Paths read the evaluation input (``agent``, ``tool``, ``action``, ``resource``, ``params``,
``context``, ``run``, ``risk``, ``time``); a missing path is ``null``.

Operators: ``== != < <= > >= in not in contains matches startswith endswith``, ``and``,
``or``, ``not`` and parentheses; functions ``len(x)``, ``lower(x)`` and ``any_of(list,
list)`` (true when the lists share an element). Two strings that are both risk levels
(low < medium < high < critical) or both sensitivities (public < internal < confidential <
restricted) compare by rank, so ``risk.level >= "high"`` means high or critical.

Errors (comparing a number with a list, a bad regex) raise :class:`EvalError`; the policy
engine then treats the rule as matching only when it denies, so a condition that cannot be
evaluated never grants anything.
"""

from __future__ import annotations

import re
from typing import Any

MAX_SOURCE = 2000
MAX_DEPTH = 32
MAX_REGEX = 200
MAX_MATCH_SUBJECT = 10_000

LEVELS = {"low": 0, "medium": 1, "high": 2, "critical": 3}
SENSITIVITIES = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}
ROOTS = (
    "agent",
    "tool",
    "action",
    "resource",
    "params",
    "context",
    "run",
    "risk",
    "time",
    "project",
    "org",
)
FUNCTIONS = ("len", "lower", "any_of")

_TOKEN = re.compile(
    r"""
    \s*(?:
      (?P<num>-?\d+(?:\.\d+)?)
    | (?P<str>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')
    | (?P<op>==|!=|<=|>=|<|>|\(|\)|\[|\]|,)
    | (?P<name>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)*)
    )""",
    re.VERBOSE,
)
_KEYWORDS = {
    "and",
    "or",
    "not",
    "in",
    "contains",
    "matches",
    "startswith",
    "endswith",
    "true",
    "false",
    "null",
}
_COMPARE = {
    "==",
    "!=",
    "<",
    "<=",
    ">",
    ">=",
    "in",
    "not in",
    "contains",
    "matches",
    "startswith",
    "endswith",
}


class ExprError(ValueError):
    """The source is not a valid expression (raised when a policy is saved)."""


class EvalError(ValueError):
    """The expression could not be evaluated against this input."""


Node = list[Any]


def _tokens(source: str) -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = []
    pos = 0
    source = source.rstrip()
    while pos < len(source):
        m = _TOKEN.match(source, pos)
        if not m or m.end() == pos:
            raise ExprError(f"Unexpected character at position {pos}: {source[pos : pos + 10]!r}")
        pos = m.end()
        if m.group("num") is not None:
            text = m.group("num")
            out.append(("lit", float(text) if "." in text else int(text)))
        elif m.group("str") is not None:
            raw = m.group("str")[1:-1]
            out.append(("lit", re.sub(r"\\(.)", r"\1", raw)))
        elif m.group("op") is not None:
            out.append(("op", m.group("op")))
        else:
            name = m.group("name")
            if name in _KEYWORDS:
                if name in ("true", "false"):
                    out.append(("lit", name == "true"))
                elif name == "null":
                    out.append(("lit", None))
                else:
                    out.append(("kw", name))
            else:
                out.append(("name", name))
    return out


class _Parser:
    def __init__(self, tokens: list[tuple[str, Any]]) -> None:
        self.tokens = tokens
        self.i = 0
        self.depth = 0

    def peek(self, offset: int = 0) -> tuple[str, Any] | None:
        j = self.i + offset
        return self.tokens[j] if j < len(self.tokens) else None

    def take(self) -> tuple[str, Any]:
        tok = self.peek()
        if tok is None:
            raise ExprError("Unexpected end of expression")
        self.i += 1
        return tok

    def expect(self, kind: str, value: Any) -> None:
        tok = self.take()
        if tok != (kind, value):
            raise ExprError(f"Expected {value!r}, found {tok[1]!r}")

    def nest(self) -> None:
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise ExprError("Expression nests too deeply")

    def parse(self) -> Node:
        node = self.or_()
        if self.peek() is not None:
            raise ExprError(f"Unexpected {self.peek()[1]!r}")  # type: ignore[index]
        return node

    def or_(self) -> Node:
        left = self.and_()
        while self.peek() == ("kw", "or"):
            self.take()
            left = ["or", left, self.and_()]
        return left

    def and_(self) -> Node:
        left = self.not_()
        while self.peek() == ("kw", "and"):
            self.take()
            left = ["and", left, self.not_()]
        return left

    def not_(self) -> Node:
        if self.peek() == ("kw", "not") and self.peek(1) != ("kw", "in"):
            self.take()
            self.nest()
            node = ["not", self.not_()]
            self.depth -= 1
            return node
        return self.compare()

    def compare(self) -> Node:
        left = self.value()
        tok = self.peek()
        op: str | None = None
        if tok is not None and tok[0] in ("op", "kw") and tok[1] in _COMPARE:
            op = tok[1]
            self.take()
        elif tok == ("kw", "not") and self.peek(1) == ("kw", "in"):
            self.take()
            self.take()
            op = "not in"
        if op is None:
            return ["truthy", left]
        right = self.value()
        if op == "matches":
            if right[0] != "lit" or not isinstance(right[1], str):
                raise ExprError("matches needs a string pattern")
            if len(right[1]) > MAX_REGEX:
                raise ExprError(f"Patterns are limited to {MAX_REGEX} characters")
            try:
                re.compile(right[1])
            except re.error as exc:
                raise ExprError(f"Invalid pattern: {exc}") from exc
        return ["cmp", op, left, right]

    def value(self) -> Node:
        tok = self.take()
        kind, val = tok
        if kind == "lit":
            return ["lit", val]
        if kind == "op" and val == "(":
            self.nest()
            node = self.or_()
            self.expect("op", ")")
            self.depth -= 1
            return ["group", node]
        if kind == "op" and val == "[":
            items: list[Any] = []
            if self.peek() != ("op", "]"):
                while True:
                    item = self.take()
                    if item[0] != "lit":
                        raise ExprError("Lists may only hold literal values")
                    items.append(item[1])
                    if self.peek() == ("op", ","):
                        self.take()
                        continue
                    break
            self.expect("op", "]")
            return ["lit", items]
        if kind == "name":
            if self.peek() == ("op", "("):
                if val not in FUNCTIONS:
                    raise ExprError(f"Unknown function {val!r} (use {', '.join(FUNCTIONS)})")
                self.take()
                args = [self.value()]
                while self.peek() == ("op", ","):
                    self.take()
                    args.append(self.value())
                self.expect("op", ")")
                if val == "any_of" and len(args) != 2:
                    raise ExprError("any_of takes two lists")
                if val != "any_of" and len(args) != 1:
                    raise ExprError(f"{val} takes one argument")
                return ["call", val, *args]
            root = val.split(".", 1)[0]
            if root not in ROOTS:
                raise ExprError(f"Unknown name {val!r}: paths start with {', '.join(ROOTS)}")
            return ["path", val.split(".")]
        raise ExprError(f"Unexpected {val!r}")


def parse(source: str) -> Node:
    """Parse an expression into its tree. Raises :class:`ExprError` with a readable message."""
    if not source or not source.strip():
        raise ExprError("Empty expression")
    if len(source) > MAX_SOURCE:
        raise ExprError(f"Expressions are limited to {MAX_SOURCE} characters")
    return _Parser(_tokens(source)).parse()


def _resolve(data: dict[str, Any], parts: list[str]) -> Any:
    cur: Any = data
    for part in parts:
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
        if cur is None:
            return None
    return cur


def _rank(a: Any, b: Any) -> tuple[int, int] | None:
    if isinstance(a, str) and isinstance(b, str):
        for scale in (LEVELS, SENSITIVITIES):
            if a in scale and b in scale:
                return scale[a], scale[b]
    return None


_NUM = (int, float)


def _ordered(op: str, a: Any, b: Any) -> bool:
    if a is None or b is None:
        return False
    ranked = _rank(a, b)
    if ranked is not None:
        a, b = ranked
    elif isinstance(a, bool) or isinstance(b, bool):
        raise EvalError("Cannot order true or false")
    elif not (
        (isinstance(a, _NUM) and isinstance(b, _NUM)) or (isinstance(a, str) and isinstance(b, str))
    ):
        raise EvalError(f"Cannot compare {type(a).__name__} with {type(b).__name__}")
    if op == "<":
        return bool(a < b)
    if op == "<=":
        return bool(a <= b)
    if op == ">":
        return bool(a > b)
    return bool(a >= b)


def _member(item: Any, container: Any) -> bool:
    if container is None:
        return False
    if isinstance(container, list | tuple | set):
        return item in container
    if isinstance(container, str) and isinstance(item, str):
        return item in container
    if isinstance(container, dict):
        return item in container
    raise EvalError(f"'in' needs a list or a string, not {type(container).__name__}")


def _cmp(op: str, a: Any, b: Any) -> bool:
    if op == "==":
        return bool(a == b)
    if op == "!=":
        return bool(a != b)
    if op in ("<", "<=", ">", ">="):
        return _ordered(op, a, b)
    if op == "in":
        return _member(a, b)
    if op == "not in":
        return not _member(a, b)
    if op == "contains":
        return _member(b, a)
    if op in ("startswith", "endswith"):
        if a is None:
            return False
        if not isinstance(a, str) or not isinstance(b, str):
            raise EvalError(f"{op} needs strings")
        return a.startswith(b) if op == "startswith" else a.endswith(b)
    if op == "matches":
        if a is None:
            return False
        if not isinstance(a, str | int | float) or isinstance(a, bool):
            raise EvalError("matches needs a string")
        subject = str(a)[:MAX_MATCH_SUBJECT]
        return re.fullmatch(str(b), subject) is not None
    raise EvalError(f"Unknown operator {op}")


def _value(node: Node, data: dict[str, Any]) -> Any:
    tag = node[0]
    if tag == "lit":
        return node[1]
    if tag == "path":
        return _resolve(data, node[1])
    if tag == "group":
        return evaluate(node[1], data)
    if tag == "call":
        name = node[1]
        args = [_value(arg, data) for arg in node[2:]]
        if name == "len":
            if args[0] is None:
                return 0
            if isinstance(args[0], str | list | dict):
                return len(args[0])
            raise EvalError("len needs a string, list or mapping")
        if name == "lower":
            return args[0].lower() if isinstance(args[0], str) else args[0]
        if name == "any_of":
            a, b = args
            if a is None or b is None:
                return False
            if not isinstance(a, list) or not isinstance(b, list):
                raise EvalError("any_of needs two lists")
            return any(x in b for x in a)
    return evaluate(node, data)


def evaluate(node: Node, data: dict[str, Any]) -> bool:
    """Evaluate a parsed expression. Raises :class:`EvalError` when it cannot be decided."""
    tag = node[0]
    if tag == "or":
        return evaluate(node[1], data) or evaluate(node[2], data)
    if tag == "and":
        return evaluate(node[1], data) and evaluate(node[2], data)
    if tag == "not":
        return not evaluate(node[1], data)
    if tag == "truthy":
        value = _value(node[1], data)
        return bool(value)
    if tag == "cmp":
        return _cmp(node[1], _value(node[2], data), _value(node[3], data))
    if tag == "group":
        return evaluate(node[1], data)
    return bool(_value(node, data))


def paths(node: Node) -> set[str]:
    """Every input path an expression reads (for the policy builder and simulation)."""
    found: set[str] = set()

    def walk(n: Any) -> None:
        if isinstance(n, list) and n:
            if n[0] == "path":
                found.add(".".join(n[1]))
                return
            for child in n[1:]:
                walk(child)

    walk(node)
    return found
