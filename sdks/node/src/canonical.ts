/**
 * Canonical JSON and the action hash, byte for byte the same as the AgentGuard API.
 *
 * AgentGuard binds approvals and decision tokens to a SHA-256 of the exact action
 * (organisation, agent, tool, action, resource key, parameters). A tool that verifies a
 * decision token recomputes it from the parameters it is about to act on, so a token issued
 * for `{ amount: 50 }` cannot be spent on `{ amount: 5000 }`.
 *
 * The API serialises with orjson; this reproduces its output for the values the API would
 * receive from this SDK (the request body is `JSON.stringify` of the parameters):
 *
 * - object keys sorted by Unicode code point, no insignificant whitespace;
 * - strings NFC normalised, only `"`, `\` and control characters escaped;
 * - integral numbers below 1e21 written as integers (that is what `JSON.stringify` sends and
 *   the API reads as an integer), other numbers in orjson's shortest float form;
 * - NaN, Infinity, BigInt, lone surrogates and integers outside 64 bits are refused.
 *
 * JavaScript has one number type, so an integer above 2**53 cannot be represented exactly:
 * keep amounts as integers in minor units below `Number.MAX_SAFE_INTEGER`, or as strings.
 */

import { createHash } from "node:crypto";

export const ACTION_HASH_PREFIX = "agentguard-action-v1\u0000";
const MAX_DEPTH = 64;
const INT_MIN = -(2 ** 63);
const INT_MAX = 2 ** 64 - 1;
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/** Compare two strings by Unicode code point (not UTF-16 code unit, as `sort()` does). */
export function compareCodePoints(a: string, b: string): number {
  const x = Array.from(a, (c) => c.codePointAt(0) ?? 0);
  const y = Array.from(b, (c) => c.codePointAt(0) ?? 0);
  const n = Math.min(x.length, y.length);
  for (let i = 0; i < n; i++) {
    const p = x[i] ?? 0;
    const q = y[i] ?? 0;
    if (p !== q) return p - q;
  }
  return x.length - y.length;
}

function encodeString(value: string): string {
  if (LONE_SURROGATE.test(value)) {
    throw new RangeError("Strings may not contain lone surrogates");
  }
  // JSON.stringify escapes exactly what orjson escapes (and lowercase \u00xx).
  return JSON.stringify(value.normalize("NFC"));
}

/** A finite, non-integral (or very large) number in orjson's notation. */
export function formatFloat(value: number): string {
  if (value === 0) return "0";
  const sign = value < 0 ? "-" : "";
  // toExponential() without digits gives the shortest round-trip digits.
  const [mantissa = "", expText = "0"] = Math.abs(value).toExponential().split("e");
  const digits = mantissa.replace(".", "").replace(/0+$/, "") || "0";
  const point = Number(expText) + 1;
  const n = digits.length;
  if (point >= n && point <= 16) return `${sign}${digits}${"0".repeat(point - n)}.0`;
  if (point > 0 && point <= 16) return `${sign}${digits.slice(0, point)}.${digits.slice(point)}`;
  if (point > -5 && point <= 0) return `${sign}0.${"0".repeat(-point)}${digits}`;
  const exponent = point - 1;
  const exp = `e${exponent >= 0 ? "+" : "-"}${Math.abs(exponent)}`;
  if (n === 1) return `${sign}${digits}${exp}`;
  return `${sign}${digits[0] ?? ""}.${digits.slice(1)}${exp}`;
}

function encodeNumber(value: number): string {
  if (!Number.isFinite(value)) throw new RangeError("Parameters may not contain NaN or infinity");
  if (Number.isInteger(value) && Math.abs(value) < 1e21) {
    if (value < INT_MIN || value > INT_MAX) throw new RangeError("Integers must fit in 64 bits");
    return String(value); // -0 prints as "0"
  }
  return formatFloat(value);
}

function isPlainObject(value: object): value is Record<string, unknown> {
  const proto: unknown = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function encode(value: unknown, depth: number, out: string[]): void {
  if (depth > MAX_DEPTH) throw new RangeError("Parameters nest too deeply");
  if (value === null) {
    out.push("null");
    return;
  }
  switch (typeof value) {
    case "boolean":
      out.push(value ? "true" : "false");
      return;
    case "string":
      out.push(encodeString(value));
      return;
    case "number":
      out.push(encodeNumber(value));
      return;
    case "object":
      break;
    default:
      throw new TypeError(`Unsupported parameter type ${typeof value}`);
  }
  const withJson = value as { toJSON?: () => unknown };
  if (typeof withJson.toJSON === "function") {
    encode(withJson.toJSON(), depth, out);
    return;
  }
  if (Array.isArray(value)) {
    out.push("[");
    value.forEach((item: unknown, index) => {
      if (index) out.push(",");
      // JSON.stringify sends undefined array items as null.
      encode(item === undefined ? null : item, depth + 1, out);
    });
    out.push("]");
    return;
  }
  if (!isPlainObject(value)) {
    throw new TypeError(`Unsupported parameter type ${value.constructor.name}`);
  }
  const items = new Map<string, unknown>();
  for (const [key, item] of Object.entries(value)) {
    // JSON.stringify drops undefined properties, so the API never sees them.
    if (item !== undefined) items.set(key.normalize("NFC"), item);
  }
  out.push("{");
  [...items.keys()].sort(compareCodePoints).forEach((key, index) => {
    if (index) out.push(",");
    out.push(encodeString(key), ":");
    encode(items.get(key), depth + 1, out);
  });
  out.push("}");
}

/** The canonical JSON text of `value` (what the API hashes, as UTF-8). */
export function canonicalJson(value: unknown): string {
  const out: string[] = [];
  encode(value, 0, out);
  return out.join("");
}

/** The hex SHA-256 action hash approvals and decision tokens are bound to. */
export function actionHash(
  orgId: string,
  agentId: string,
  tool: string,
  action: string,
  resource: string,
  params: Record<string, unknown> | undefined | null,
): string {
  const body = canonicalJson({
    org: orgId,
    agent: agentId,
    tool,
    action,
    resource,
    params: params ?? {},
  });
  return createHash("sha256").update(ACTION_HASH_PREFIX + body, "utf8").digest("hex");
}
