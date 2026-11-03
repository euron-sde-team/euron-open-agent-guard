"""Canonical JSON and the action hash, byte for byte the same as the AgentGuard API.

AgentGuard binds approvals and decision tokens to a hash of the exact action: the
organisation, the agent, the tool, the action, the resource key and the parameters. A tool
that verifies a decision token recomputes that hash from the parameters it is about to act
on, so a token issued for ``{"amount": 50}`` cannot be spent on ``{"amount": 5000}``.

The API serialises with orjson. This module reproduces its output without depending on it:

* object keys sorted by Unicode code point, no insignificant whitespace;
* strings NFC normalised, only ``"``, ``\\`` and control characters escaped, everything
  else written as raw UTF-8;
* a float that is integral and below 2**53 in magnitude is written as an integer
  (``5.0`` and ``5`` are the same amount), other floats in orjson's shortest form;
* NaN and infinity are refused, as are integers outside the signed and unsigned 64-bit
  range (the API cannot hash them either).

Prefer integers (minor units) or strings for amounts: two runtimes always agree on them.
"""

from __future__ import annotations

import hashlib
import json
import math
import unicodedata
from collections.abc import Mapping
from decimal import Decimal
from typing import Any

ACTION_HASH_PREFIX = b"agentguard-action-v1\x00"
MAX_DEPTH = 64
_INT_MIN = -(2**63)
_INT_MAX = 2**64 - 1


def _string(value: str) -> str:
    normal = unicodedata.normalize("NFC", value)
    # json.dumps with ensure_ascii=False escapes exactly what orjson escapes.
    return json.dumps(normal, ensure_ascii=False)


def format_float(value: float) -> str:
    """A non-integral (or very large) finite float in orjson's notation."""
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    # repr gives the shortest digits that round-trip, like orjson's formatter.
    parsed = Decimal(repr(abs(value))).normalize().as_tuple()
    digits = "".join(str(d) for d in parsed.digits)
    assert isinstance(parsed.exponent, int)
    # The decimal point position relative to the start of ``digits``.
    point = len(digits) + parsed.exponent
    n = len(digits)
    if point >= n and point <= 16:
        return f"{sign}{digits}{'0' * (point - n)}.0"
    if 0 < point <= 16:
        return f"{sign}{digits[:point]}.{digits[point:]}"
    if -5 < point <= 0:
        return f"{sign}0.{'0' * (-point)}{digits}"
    exponent = point - 1
    exp = f"e{'+' if exponent >= 0 else '-'}{abs(exponent)}"
    if n == 1:
        return f"{sign}{digits}{exp}"
    return f"{sign}{digits[0]}.{digits[1:]}{exp}"


def _encode(value: Any, depth: int, out: list[str]) -> None:
    if depth > MAX_DEPTH:
        raise ValueError("Parameters nest too deeply")
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, str):
        out.append(_string(value))
    elif isinstance(value, int):
        if not _INT_MIN <= value <= _INT_MAX:
            raise ValueError("Integers must fit in 64 bits")
        out.append(str(int(value)))
    elif isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("Parameters may not contain NaN or infinity")
        if value.is_integer() and abs(value) < 2**53:
            out.append(str(int(value)))
        else:
            out.append(format_float(value))
    elif isinstance(value, Mapping):
        items: dict[str, Any] = {}
        for key, item in value.items():
            items[unicodedata.normalize("NFC", str(key))] = item
        out.append("{")
        for index, key in enumerate(sorted(items)):
            if index:
                out.append(",")
            out.append(_string(key))
            out.append(":")
            _encode(items[key], depth + 1, out)
        out.append("}")
    elif isinstance(value, list | tuple):
        out.append("[")
        for index, item in enumerate(value):
            if index:
                out.append(",")
            _encode(item, depth + 1, out)
        out.append("]")
    else:
        raise ValueError(f"Unsupported parameter type {type(value).__name__}")


def canonical_json(value: Any) -> bytes:
    """The canonical UTF-8 JSON bytes of ``value`` (what the API hashes)."""
    out: list[str] = []
    _encode(value, 0, out)
    try:
        return "".join(out).encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("Strings may not contain lone surrogates") from exc


def action_hash(
    org_id: object,
    agent_id: object,
    tool: str,
    action: str,
    resource: str,
    params: Mapping[str, Any] | None,
) -> str:
    """The hex SHA-256 action hash approvals and decision tokens are bound to."""
    body = canonical_json(
        {
            "org": str(org_id),
            "agent": str(agent_id),
            "tool": tool,
            "action": action,
            "resource": resource,
            "params": dict(params or {}),
        }
    )
    return hashlib.sha256(ACTION_HASH_PREFIX + body).hexdigest()
