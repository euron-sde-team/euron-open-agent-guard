"""Canonical JSON and the action hash that approvals and decision tokens are bound to.

Two requests for the same action must hash the same however their JSON was written (key
order, whitespace, Unicode composition), and any difference in what would happen must
change the hash. So: keys sorted, no insignificant whitespace, strings NFC-normalised,
integral floats written as integers (``5.0`` and ``5`` mean the same amount), and the
organisation, agent, tool, action and resource included next to the parameters.
"""

from __future__ import annotations

import hashlib
import math
import unicodedata
from typing import Any

import orjson


def _normal(value: Any, depth: int = 0) -> Any:
    if depth > 64:
        raise ValueError("Parameters nest too deeply")
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("Parameters may not contain NaN or infinity")
        return int(value) if value.is_integer() and abs(value) < 2**53 else value
    if isinstance(value, dict):
        return {
            unicodedata.normalize("NFC", str(k)): _normal(v, depth + 1) for k, v in value.items()
        }
    if isinstance(value, list | tuple):
        return [_normal(v, depth + 1) for v in value]
    raise ValueError(f"Unsupported parameter type {type(value).__name__}")


def canonical_json(value: Any) -> bytes:
    return orjson.dumps(_normal(value), option=orjson.OPT_SORT_KEYS)


def action_hash(
    org_id: object, agent_id: object, tool: str, action: str, resource: str, params: Any
) -> str:
    body = canonical_json(
        {
            "org": str(org_id),
            "agent": str(agent_id),
            "tool": tool,
            "action": action,
            "resource": resource,
            "params": params,
        }
    )
    return hashlib.sha256(b"agentguard-action-v1\x00" + body).hexdigest()
