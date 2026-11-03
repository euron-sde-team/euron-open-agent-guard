"""The action hash matches the API byte for byte (vectors generated from apps/api)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from euron_agentguard import action_hash, canonical_json
from euron_agentguard._core import signature
from euron_agentguard.canonical import format_float

VECTORS = json.loads(
    (Path(__file__).parents[3] / "testdata" / "action-hash-vectors.json").read_text("utf-8")
)


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["name"])
def test_case(case: dict[str, Any]) -> None:
    params = json.loads(case["params_json"])
    assert canonical_json(params).decode() == case["canonical_params"]
    assert (
        action_hash(
            case["org"], case["agent"], case["tool"], case["action"], case["resource"], params
        )
        == case["hash"]
    )


def test_floats() -> None:
    mismatches = [
        (f["json"], canonical_json(json.loads(f["json"])).decode(), f["canonical"])
        for f in VECTORS["floats"]
        if canonical_json(json.loads(f["json"])).decode() != f["canonical"]
    ]
    assert len(VECTORS["floats"]) == 2000
    assert mismatches == []


@pytest.mark.parametrize("case", VECTORS["signatures"], ids=lambda c: c["nonce"])
def test_signature(case: dict[str, str]) -> None:
    assert (
        signature(case["secret"], case["timestamp"], case["nonce"], case["body"].encode())
        == case["signature"]
    )


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf")])
def test_refuses_non_finite(value: float) -> None:
    with pytest.raises(ValueError, match="NaN"):
        canonical_json({"a": value})


def test_refuses_out_of_range_integers_and_unknown_types() -> None:
    with pytest.raises(ValueError, match="64 bits"):
        canonical_json(2**64)
    with pytest.raises(ValueError, match="64 bits"):
        canonical_json(-(2**63) - 1)
    with pytest.raises(ValueError, match="Unsupported"):
        canonical_json({"when": object()})
    with pytest.raises(ValueError, match="surrogates"):
        canonical_json("\ud800")


def test_refuses_deep_nesting() -> None:
    value: Any = 1
    for _ in range(70):
        value = [value]
    with pytest.raises(ValueError, match="deeply"):
        canonical_json(value)


def test_shapes() -> None:
    assert canonical_json({"b": (1, 2), "a": {"y": None, "x": True}}) == (
        b'{"a":{"x":true,"y":null},"b":[1,2]}'
    )
    assert canonical_json(5.0) == b"5"
    assert canonical_json(-0.0) == b"0"
    assert canonical_json(True) == b"true"
    assert format_float(0.0) == "0"
    assert format_float(-2.5) == "-2.5"
    assert format_float(1e16) == "1e+16"
    assert format_float(9007199254740992.0) == "9007199254740992.0"
    assert action_hash("o", "a", "t", "call", "", None) == action_hash(
        "o", "a", "t", "call", "", {}
    )
