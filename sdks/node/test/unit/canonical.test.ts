import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { actionHash, canonicalJson, compareCodePoints, formatFloat, signature } from "../../src/index.js";

interface Case {
  name: string;
  org: string;
  agent: string;
  tool: string;
  action: string;
  resource: string;
  params_json: string;
  python_only: boolean;
  canonical_params: string;
  hash: string;
}

const vectors = JSON.parse(
  readFileSync(fileURLToPath(new URL("../../../testdata/action-hash-vectors.json", import.meta.url)), "utf8"),
) as {
  cases: Case[];
  floats: { json: string; canonical: string }[];
  signatures: { secret: string; timestamp: string; nonce: string; body: string; signature: string }[];
};

describe("action hash vectors (generated from apps/api)", () => {
  const shared = vectors.cases.filter((c) => !c.python_only);

  it("has the shared and the Python-only cases", () => {
    expect(shared.length).toBe(17);
    expect(vectors.cases.length - shared.length).toBe(3);
  });

  it.each(shared.map((c) => [c.name, c] as const))("%s", (_name, c) => {
    const params = JSON.parse(c.params_json) as Record<string, unknown>;
    expect(canonicalJson(params)).toBe(c.canonical_params);
    expect(actionHash(c.org, c.agent, c.tool, c.action, c.resource, params)).toBe(c.hash);
  });

  it("matches all 2000 floats", () => {
    const wrong = vectors.floats.filter((f) => canonicalJson(JSON.parse(f.json)) !== f.canonical);
    expect(vectors.floats.length).toBe(2000);
    expect(wrong).toEqual([]);
  });

  it.each(vectors.signatures.map((s) => [s.nonce, s] as const))("signature %s", (_n, s) => {
    expect(signature(s.secret, s.timestamp, s.nonce, s.body)).toBe(s.signature);
  });
});

describe("canonical JSON", () => {
  it("refuses what the API cannot hash", () => {
    expect(() => canonicalJson({ a: NaN })).toThrow(/NaN/);
    expect(() => canonicalJson({ a: Infinity })).toThrow(/NaN/);
    expect(() => canonicalJson({ a: 10n })).toThrow(/Unsupported/);
    expect(() => canonicalJson({ a: () => 1 })).toThrow(/Unsupported/);
    expect(() => canonicalJson({ a: new Map() })).toThrow(/Unsupported/);
    expect(() => canonicalJson("\ud800")).toThrow(/surrogates/);
    expect(() => canonicalJson(-(2 ** 64))).toThrow(/64 bits/);
    let deep: unknown = 1;
    for (let i = 0; i < 70; i++) deep = [deep];
    expect(() => canonicalJson(deep)).toThrow(/deeply/);
  });

  it("mirrors what JSON.stringify sends", () => {
    expect(canonicalJson({ b: [1, undefined], a: { y: null, x: true, z: undefined } })).toBe(
      '{"a":{"x":true,"y":null},"b":[1,null]}',
    );
    expect(canonicalJson({ when: new Date("2026-01-02T03:04:05Z") })).toBe('{"when":"2026-01-02T03:04:05.000Z"}');
    expect(canonicalJson(Object.assign(Object.create(null) as object, { k: false }))).toBe('{"k":false}');
    expect(canonicalJson(-0)).toBe("0");
    expect(canonicalJson(5)).toBe("5");
    expect(canonicalJson(1e21)).toBe("1e+21");
    expect(canonicalJson(2 ** 60)).toBe(String(2 ** 60));
  });

  it("formats floats like orjson", () => {
    expect(formatFloat(0)).toBe("0");
    expect(formatFloat(-2.5)).toBe("-2.5");
    expect(formatFloat(1e16)).toBe("1e+16");
    expect(formatFloat(9007199254740992)).toBe("9007199254740992.0");
    expect(formatFloat(1e-5)).toBe("0.00001");
    expect(formatFloat(1e-6)).toBe("1e-6");
    expect(formatFloat(1.5e-7)).toBe("1.5e-7");
  });

  it("sorts keys by code point", () => {
    expect(["￿", "\u{1f600}", "a"].sort(compareCodePoints)).toEqual(["a", "￿", "\u{1f600}"]);
    expect(compareCodePoints("ab", "a")).toBeGreaterThan(0);
    expect(actionHash("o", "a", "t", "call", "", null)).toBe(actionHash("o", "a", "t", "call", "", {}));
  });
});
