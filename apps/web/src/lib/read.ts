/**
 * Small, total readers for JSON the contract types as free-form objects. Each returns a
 * sensible default instead of throwing, so a missing field degrades the UI, never
 * crashes it.
 */
export type Json = Record<string, unknown>;

export function obj(v: unknown): Json {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Json) : {};
}

export function str(v: unknown): string | null {
  return typeof v === "string" ? v : null;
}

export function num(v: unknown): number | null {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && v.trim() !== "" && Number.isFinite(Number(v))) return Number(v);
  return null;
}

export function bool(v: unknown): boolean {
  return v === true;
}

export function strs(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
}

export function counts(v: unknown): Record<string, number> {
  const out: Record<string, number> = {};
  for (const [k, n] of Object.entries(obj(v))) {
    const x = num(n);
    if (x != null) out[k] = x;
  }
  return out;
}

export function arr(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}
