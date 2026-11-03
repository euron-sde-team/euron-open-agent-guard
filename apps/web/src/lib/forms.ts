/** Small parsers for form fields, total and side-effect free. */

/** "a, b,,c" or "a\nb" becomes ["a", "b", "c"]; duplicates dropped, order kept. */
export function splitList(value: string): string[] {
  const out: string[] = [];
  for (const part of value.split(/[,\n]/)) {
    const t = part.trim();
    if (t && !out.includes(t)) out.push(t);
  }
  return out;
}

export function joinList(values: readonly string[] | null | undefined): string {
  return (values ?? []).join(", ");
}

/** Parse a JSON object typed by a person; returns the object or a readable error. */
export function parseJsonObject(text: string): { value: Record<string, unknown> } | { error: string } {
  const t = text.trim();
  if (!t) return { value: {} };
  let parsed: unknown;
  try {
    parsed = JSON.parse(t);
  } catch (e) {
    return { error: `Not valid JSON: ${e instanceof Error ? e.message : "check commas and quotes"}` };
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return { error: "Write a JSON object, like {\"amount\": 120}." };
  return { value: parsed as Record<string, unknown> };
}

/** "team=finance, tier=2, pii=true" becomes {team: "finance", tier: 2, pii: true}. */
export function parseLabels(value: string): Record<string, string | number | boolean> {
  const out: Record<string, string | number | boolean> = {};
  for (const pair of splitList(value)) {
    const i = pair.indexOf("=");
    if (i <= 0) continue;
    const k = pair.slice(0, i).trim();
    const raw = pair.slice(i + 1).trim();
    if (!k) continue;
    if (raw === "true" || raw === "false") out[k] = raw === "true";
    else if (raw !== "" && /^-?\d+(\.\d+)?$/.test(raw)) out[k] = Number(raw);
    else out[k] = raw;
  }
  return out;
}

export function formatLabels(labels: Record<string, unknown> | null | undefined): string {
  return Object.entries(labels ?? {})
    .map(([k, v]) => `${k}=${String(v)}`)
    .join(", ");
}

/** A slug the API accepts: lower case letters, digits and dashes. */
export function slugify(value: string): string {
  return value
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 60);
}

export function parsePorts(value: string): number[] {
  return splitList(value)
    .map(Number)
    .filter((n) => Number.isInteger(n) && n >= 1 && n <= 65535);
}

/** "Authorization: Bearer {secret:crm-key}" lines to {Authorization: "Bearer {secret:crm-key}"}. */
export function parseHeaderLines(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split("\n")) {
    const i = line.indexOf(":");
    if (i <= 0) continue;
    const k = line.slice(0, i).trim();
    const v = line.slice(i + 1).trim();
    if (k && v) out[k] = v;
  }
  return out;
}

export function formatHeaderLines(headers: Record<string, unknown> | null | undefined): string {
  return Object.entries(headers ?? {})
    .map(([k, v]) => `${k}: ${String(v)}`)
    .join("\n");
}

/**
 * An example parameter object for a JSON schema: its required properties (or all, when
 * none are required) with a value of the declared type, an enum's first value or a
 * default. Used to prefill the policy Test panel.
 */
export function exampleParams(schema: unknown): Record<string, unknown> {
  const s = typeof schema === "object" && schema !== null ? (schema as Record<string, unknown>) : {};
  const props = typeof s.properties === "object" && s.properties !== null ? (s.properties as Record<string, Record<string, unknown>>) : {};
  const required = Array.isArray(s.required) ? s.required.filter((r): r is string => typeof r === "string") : [];
  const keys = required.length ? required : Object.keys(props);
  const out: Record<string, unknown> = {};
  for (const k of keys) {
    const p = props[k] ?? {};
    if (p.default !== undefined) out[k] = p.default;
    else if (Array.isArray(p.enum) && p.enum.length) out[k] = p.enum[0];
    else if (p.type === "integer" || p.type === "number") out[k] = 100;
    else if (p.type === "boolean") out[k] = false;
    else if (p.type === "array") out[k] = [];
    else if (p.type === "object") out[k] = {};
    else out[k] = "example";
  }
  return out;
}
