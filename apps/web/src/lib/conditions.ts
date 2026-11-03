/**
 * Helpers for the condition language of policies, permissions and risk rules (the API's
 * policies/expr.py). The API is the authority: it parses and validates every condition.
 * These helpers build conditions from form fields and catch the obvious mistakes
 * (unbalanced quotes or parentheses, unknown roots) while the person types.
 */

export const ROOTS = ["agent", "tool", "action", "resource", "params", "context", "run", "risk", "time", "project"] as const;

export const OPERATORS = ["==", "!=", "<", "<=", ">", ">=", "in", "not in", "contains", "matches", "startswith", "endswith"] as const;
export type Operator = (typeof OPERATORS)[number];

/** Paths people reach for most, for pickers and hints. */
export const COMMON_PATHS = [
  "params.amount",
  "risk.level",
  "risk.score",
  "resource.sensitivity",
  "resource.environment",
  "resource.registered",
  "resource.owned",
  "tool.external",
  "tool.sensitive",
  "agent.labels.team",
  "context.data_classes",
  "run.tainted",
  "run.tool_calls",
  "time.hour",
  "time.weekday",
] as const;

export const CONDITION_EXAMPLES = [
  "params.amount > 500",
  'risk.level >= "high"',
  'context.data_classes contains "pii"',
  'resource.sensitivity in ["confidential", "restricted"]',
  'time.hour < 8 or time.weekday in ["sat", "sun"]',
  "run.tainted and tool.external",
  'params.to matches ".*@corp\\\\.example"',
];

const KEYWORDS = new Set(["and", "or", "not", "in", "contains", "matches", "startswith", "endswith", "true", "false", "null", "len", "lower", "any_of"]);

/** Render a value as a literal of the language: numbers and booleans bare, strings quoted, lists bracketed. */
export function literal(value: string | number | boolean | null | readonly (string | number)[]): string {
  if (value === null) return "null";
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) return `[${value.map((v) => literal(v)).join(", ")}]`;
  const s = String(value);
  return `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

/**
 * A value typed in a form field, as a literal: "500" stays a number, "true" a boolean,
 * "a, b" for in / not in becomes a list, anything else a quoted string.
 */
export function parseValue(raw: string, op: Operator): string {
  const t = raw.trim();
  if (op === "in" || op === "not in") {
    const items = t
      .replace(/^\[|\]$/g, "")
      .split(",")
      .map((x) => x.trim().replace(/^["']|["']$/g, ""))
      .filter(Boolean)
      .map((x) => (/^-?\d+(\.\d+)?$/.test(x) ? Number(x) : x));
    return literal(items);
  }
  if (/^-?\d+(\.\d+)?$/.test(t)) return t;
  if (t === "true" || t === "false" || t === "null") return t;
  if (/^".*"$/.test(t) || /^'.*'$/.test(t)) return t;
  return literal(t);
}

export function buildCondition(path: string, op: Operator, value: string): string {
  return `${path.trim()} ${op} ${parseValue(value, op)}`;
}

/** Join non-empty conditions with and/or, parenthesising compound parts. */
export function joinConditions(parts: string[], joiner: "and" | "or" = "and"): string {
  const clean = parts.map((p) => p.trim()).filter(Boolean);
  if (clean.length <= 1) return clean[0] ?? "";
  return clean.map((p) => (/\s(and|or)\s/.test(p) && !/^\(.*\)$/.test(p) ? `(${p})` : p)).join(` ${joiner} `);
}

/**
 * The first obvious problem with a condition, or null. Empty is fine (no condition).
 * Checks quotes, parentheses and brackets, and that every bare name starts with a known
 * root or is a keyword. The API still validates fully.
 */
export function conditionIssue(source: string): string | null {
  const s = source.trim();
  if (!s) return null;
  if (s.length > 2000) return "Conditions are limited to 2000 characters.";
  let quote: string | null = null;
  const stack: string[] = [];
  const pairs: Record<string, string> = { ")": "(", "]": "[" };
  let names = "";
  for (let i = 0; i < s.length; i++) {
    const c = s[i] as string;
    if (quote) {
      if (c === "\\") {
        i++;
        continue;
      }
      if (c === quote) quote = null;
      names += " ";
      continue;
    }
    if (c === '"' || c === "'") {
      quote = c;
      names += " ";
      continue;
    }
    if (c === "(" || c === "[") stack.push(c);
    else if (c === ")" || c === "]") {
      if (stack.pop() !== pairs[c]) return `Unbalanced "${c}".`;
    }
    names += c;
  }
  if (quote) return "A string is missing its closing quote.";
  if (stack.length) return `Unclosed "${stack[stack.length - 1]}".`;
  for (const m of names.matchAll(/[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)*/g)) {
    const word = m[0];
    const root = word.split(".")[0] as string;
    if (KEYWORDS.has(word) || KEYWORDS.has(root)) continue;
    if (!(ROOTS as readonly string[]).includes(root)) return `"${word}" does not start with a known root (${ROOTS.join(", ")}).`;
  }
  return null;
}
