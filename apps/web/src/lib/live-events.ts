import { qk } from "./query-keys";

/**
 * Live updates over the dashboard WebSocket carry small invalidations, never data (see
 * the API's realtime/router.py): the client refetches what changed over REST. This module
 * is the pure part: parse a frame, decide which query keys it invalidates, and how long to
 * wait before reconnecting.
 */

export interface LiveEvent {
  type: string;
  id?: string;
  agent_id?: string;
  status?: string;
  severity?: string;
  decision?: string;
  active?: boolean;
}

/** Parse one frame; anything that is not a JSON object with a string type is ignored. */
export function parseLiveEvent(raw: unknown): LiveEvent | null {
  if (typeof raw !== "string" || raw.length > 8000) return null;
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch {
    return null;
  }
  if (typeof data !== "object" || data === null || Array.isArray(data)) return null;
  const ev = data as Record<string, unknown>;
  if (typeof ev.type !== "string") return null;
  const out: LiveEvent = { type: ev.type };
  for (const key of ["id", "agent_id", "status", "severity", "decision"] as const) {
    if (typeof ev[key] === "string") out[key] = ev[key] as string;
  }
  if (typeof ev.active === "boolean") out.active = ev.active;
  return out;
}

type Key = readonly unknown[];

/** Which React Query keys a dashboard event invalidates. */
export function dashboardKeysFor(event: LiveEvent): Key[] {
  switch (event.type) {
    case "decision":
      return [qk.metrics, qk.decisions, qk.agents, qk.risk];
    case "approval": {
      const keys: Key[] = [qk.approvals, qk.metrics];
      if (event.id) keys.push(qk.approval(event.id));
      return keys;
    }
    case "threat":
      return [qk.threats, qk.metrics, qk.agents];
    case "incident": {
      const keys: Key[] = [qk.incidents, qk.metrics];
      if (event.id) keys.push(qk.incident(event.id));
      return keys;
    }
    case "kill_switch":
      return [qk.settings, qk.metrics];
    case "agent.status": {
      const keys: Key[] = [qk.agents, qk.metrics];
      if (event.agent_id) keys.push(qk.agent(event.agent_id));
      return keys;
    }
    default:
      // ready and ping change no server state.
      return [];
  }
}

/**
 * Exponential backoff with full jitter, capped: 1 s, 2 s, 4 s ... up to 30 s. `random`
 * is injectable so tests are deterministic.
 */
export function reconnectDelay(attempt: number, random: () => number = Math.random): number {
  const base = Math.min(30_000, 1000 * 2 ** Math.max(0, attempt));
  return Math.round(base / 2 + (random() * base) / 2);
}

/**
 * The WebSocket URL for a path. Sockets go through this origin (Next proxies /ws to the
 * API, so the session cookie travels); `NEXT_PUBLIC_WS_URL` points sockets straight at the
 * API when a proxy in front of Next cannot upgrade connections.
 */
export function socketUrl(path: string, location: { protocol: string; host: string }, override?: string | null): string {
  if (override) return `${override.replace(/\/+$/, "")}${path}`;
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${location.host}${path}`;
}
