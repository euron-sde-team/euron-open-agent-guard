"""Generate the cross-language test vectors from the API's own implementation.

Run from apps/api so the real ``agentguard`` package is importable:

    cd apps/api && uv run python ../../sdks/testdata/generate_vectors.py

Every SDK must reproduce ``canonical`` and ``hash`` for every case, and ``signature`` for
every signed request case. Parameters are given as JSON text, because that is what an SDK
sends and what the API parses: a case is about the value a JSON parser produces.
"""

from __future__ import annotations

import json
import random
import struct
from pathlib import Path

from agentguard.core.canonical import action_hash, canonical_json
from agentguard.identity.service import signature

ORG = "83bf425d-2fe8-4a56-8845-70ba8ea89211"
AGENT = "1851cc95-2f4b-41ef-a78f-872411cf1add"

# (name, tool, action, resource, params as JSON text, python_only)
# python_only: JSON text whose number is an integral float of 2**53 or more. Python parses
# "9007199254740994.0" as a float and the API writes it with ".0"; JavaScript has a single
# number type, so a Node SDK would have sent it as the integer 9007199254740994 instead.
# Integers beyond 2**53 are python_only too: a JavaScript number cannot hold them exactly.
CASES: list[tuple[str, str, str, str, str, bool]] = [
    ("empty", "refunds", "create", "", "{}", False),
    ("simple", "refunds", "create", "customer:c1", '{"amount": 50, "customer": "c1"}', False),
    ("key order", "refunds", "create", "customer:c1", '{"customer": "c1", "amount": 50}', False),
    ("integral float", "refunds", "create", "customer:c1", '{"amount": 50.0}', False),
    ("negative zero", "t", "call", "", '{"x": -0.0}', False),
    ("decimal", "payments", "send", "", '{"amount": 12.75, "rate": 0.1}', False),
    ("small float", "t", "call", "", '{"a": 1e-5, "b": 1e-6, "c": 1.5e-7, "d": 0.000123}', False),
    ("large float", "t", "call", "", '{"a": 1e21, "b": 1.7976931348623157e308}', False),
    ("big integer", "t", "call", "", '{"a": 9007199254740993, "b": -9223372036854775808}', True),
    ("max u64", "t", "call", "", '{"a": 18446744073709551615}', True),
    ("big float", "t", "call", "", '{"a": 9007199254740994.0, "b": 1e16}', True),
    ("nested", "db", "query", "database:prod", '{"q": {"z": [1, {"b": 2, "a": 1}], "a": null, "t": true, "f": false}}', False),
    ("escapes", "mail", "send", "", '{"body": "a\\"b\\\\c\\n\\t\\r\\b\\f\\u0000\\u001f\\u007f / < > &"}', False),
    ("line separators", "mail", "send", "", '{"body": "x\\u2028y\\u2029z"}', False),
    ("nfc", "crm", "update", "", '{"name": "Rene\\u0301", "Ren\\u00e9": 1}', False),
    ("astral keys", "t", "call", "", '{"\\uffff": 1, "\\ud83d\\ude00": 2, "a": 3, "B": 4, "\\u00e9": 5}', False),
    ("unicode text", "t", "call", "", '{"text": "\\u65e5\\u672c\\u8a9e \\ud83d\\ude80"}', False),
    ("array of objects", "t", "call", "", '{"rows": [{"id": 2, "v": 2.5}, {"id": 1, "v": -3.25}]}', False),
    ("unicode resource", "files", "read", "file:caf\\u00e9.txt", '{"path": "/tmp/x"}', False),
    ("deep", "t", "call", "", '{"a": {"b": {"c": {"d": {"e": [[[[1]]]]}}}}}', False),
]

SIGNED: list[tuple[str, str, str, str]] = [
    ("ags_test_signing_secret", "1767225600", "nonce-0123456789abcdef", '{"tool":"refunds"}'),
    ("s3cret", "1700000000", "AbCdEfGhIjKlMnOp", ""),
    ("unicode-secret-é", "1767225601", "n_" + "x" * 30, '{"a":"é"}'),
]


def _floats(count: int) -> list[dict[str, object]]:
    rng = random.Random(20261102)
    out: list[dict[str, object]] = []
    while len(out) < count:
        kind = rng.random()
        if kind < 0.4:
            value = struct.unpack("d", struct.pack("Q", rng.getrandbits(64)))[0]
        elif kind < 0.7:
            value = rng.random() * 10 ** rng.randint(-30, 30)
        else:
            value = round(rng.uniform(-100_000, 100_000), rng.randint(1, 6))
        if value != value or value in (float("inf"), float("-inf")):
            continue
        if value.is_integer():
            continue
        out.append({"json": repr(value), "canonical": canonical_json(value).decode()})
    return out


def main() -> None:
    cases = []
    for name, tool, action, resource_json, params_json, python_only in CASES:
        params = json.loads(params_json)
        resource = json.loads(f'"{resource_json}"')
        cases.append(
            {
                "name": name,
                "org": ORG,
                "agent": AGENT,
                "tool": tool,
                "action": action,
                "resource": resource,
                "params_json": params_json,
                "python_only": python_only,
                "canonical_params": canonical_json(params).decode(),
                "hash": action_hash(ORG, AGENT, tool, action, resource, params),
            }
        )
    signed = [
        {
            "secret": secret,
            "timestamp": ts,
            "nonce": nonce,
            "body": body,
            "signature": signature(secret, ts, nonce, body.encode()),
        }
        for secret, ts, nonce, body in SIGNED
    ]
    errors = [
        {"name": "nan", "params_json": '{"a": NaN}'},
        {"name": "infinity", "params_json": '{"a": Infinity}'},
    ]
    doc = {
        "about": "Generated by sdks/testdata/generate_vectors.py from apps/api (agentguard.core.canonical).",
        "cases": cases,
        "floats": _floats(2000),
        "signatures": signed,
        "errors": errors,
    }
    target = Path(__file__).with_name("action-hash-vectors.json")
    target.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {len(cases)} cases, {len(doc['floats'])} floats, {len(signed)} signatures")


if __name__ == "__main__":
    main()
