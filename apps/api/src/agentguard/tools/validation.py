"""Parameter validation: the tool's JSON schema, then its constraints.

Validation runs before anything else in the decision pipeline: a request with parameters
the tool does not accept is denied (``invalid_parameters``) with every problem listed, so a
model can read the error and correct itself. Constraints narrow what a schema allows::

    {"amount": {"max": 500}, "currency": {"one_of": ["EUR", "USD"]},
     "to": {"pattern": "[^@]+@corp\\\\.example"}, "query": {"max_length": 200,
     "forbidden": ["DROP", "DELETE"]}}
"""

from __future__ import annotations

import re
import string
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

MAX_ERRORS = 10
CONSTRAINT_KEYS = {
    "min",
    "max",
    "pattern",
    "one_of",
    "max_length",
    "min_length",
    "equals",
    "forbidden",
    "required",
}


def check_schema(schema: dict[str, Any]) -> None:
    """Raise ValueError when a tool's input schema is not valid JSON schema."""
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        raise ValueError(f"Invalid input schema: {exc.message}") from exc


def check_constraints(constraints: dict[str, Any]) -> None:
    for name, rule in constraints.items():
        if not isinstance(rule, dict):
            raise ValueError(f"Constraint for {name} must be a mapping")
        unknown = set(rule) - CONSTRAINT_KEYS
        if unknown:
            raise ValueError(f"Unknown constraint keys for {name}: {sorted(unknown)}")
        if "pattern" in rule:
            if len(str(rule["pattern"])) > 300:
                raise ValueError(f"Pattern for {name} is too long")
            try:
                re.compile(str(rule["pattern"]))
            except re.error as exc:
                raise ValueError(f"Invalid pattern for {name}: {exc}") from exc


def _get(params: dict[str, Any], dotted: str) -> tuple[bool, Any]:
    cur: Any = params
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return False, None
        cur = cur[part]
    return True, cur


def validate(
    params: dict[str, Any], schema: dict[str, Any], constraints: dict[str, Any]
) -> list[str]:
    """Every problem with these parameters (empty when valid)."""
    problems: list[str] = []
    if schema:
        validator = Draft202012Validator(schema)
        for err in sorted(validator.iter_errors(params), key=lambda e: list(e.path))[:MAX_ERRORS]:
            where = ".".join(str(p) for p in err.path) or "parameters"
            problems.append(f"{where}: {err.message}")
    for name, rule in constraints.items():
        present, value = _get(params, name)
        if not present:
            if rule.get("required"):
                problems.append(f"{name}: is required")
            continue
        if "equals" in rule and value != rule["equals"]:
            problems.append(f"{name}: must be {rule['equals']!r}")
        if "one_of" in rule and value not in rule["one_of"]:
            problems.append(f"{name}: must be one of {rule['one_of']}")
        if isinstance(value, int | float) and not isinstance(value, bool):
            if "min" in rule and value < rule["min"]:
                problems.append(f"{name}: must be at least {rule['min']}")
            if "max" in rule and value > rule["max"]:
                problems.append(f"{name}: must be at most {rule['max']}")
        if isinstance(value, str):
            if "max_length" in rule and len(value) > rule["max_length"]:
                problems.append(f"{name}: must be at most {rule['max_length']} characters")
            if "min_length" in rule and len(value) < rule["min_length"]:
                problems.append(f"{name}: must be at least {rule['min_length']} characters")
            if "pattern" in rule and re.fullmatch(str(rule["pattern"]), value[:10_000]) is None:
                problems.append(f"{name}: does not match the allowed pattern")
            for word in rule.get("forbidden", []):
                if str(word).lower() in value.lower():
                    problems.append(f"{name}: may not contain {word!r}")
        elif ("pattern" in rule or "max_length" in rule) and value is not None:
            problems.append(f"{name}: must be text")
        if len(problems) >= MAX_ERRORS:
            break
    return problems[:MAX_ERRORS]


_FORMATTER = string.Formatter()


def template_fields(template: str) -> list[str]:
    return [field for _, field, _, _ in _FORMATTER.parse(template) if field]


def render_resource(template: str, params: dict[str, Any]) -> str:
    """``customer:{customer_id}`` with the parameter filled in. Only plain parameter names
    are allowed (no attribute or index access), and values may not contain separators that
    would let a parameter change the resource type."""
    if not template:
        return ""
    out = []
    for literal, field, _, _ in _FORMATTER.parse(template):
        out.append(literal)
        if not field:
            continue
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", field):
            raise ValueError(f"Resource template field {field!r} must be a parameter name")
        value = params.get(field)
        if value is None or isinstance(value, dict | list):
            return ""
        text = str(value)
        if ":" in text or "*" in text or len(text) > 200:
            raise ValueError(f"{field} cannot be used in a resource name")
        out.append(text)
    return "".join(out)
