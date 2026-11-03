/** The agent side: `AgentGuard` (authorize, execute, scan, approvals, guard wrapper). */

import { AsyncLocalStorage } from "node:async_hooks";
import { createHash, createHmac, randomBytes } from "node:crypto";

import { APIError, ApprovalRequired, GuardUnavailable } from "./errors.js";
import {
  type AgentIdentity,
  ApprovalStatus,
  Decision,
  type DecisionInit,
  type ScanResult,
  agentIdentity,
  scanResult,
} from "./models.js";

export const VERSION = "0.1.0";
const USER_AGENT = `euron-agentguard-node/${VERSION}`;
const REFRESH_CODES = new Set(["invalid_token", "token_revoked"]);
const RUN_ID = /^[A-Za-z0-9_.:@/-]{1,128}$/;
const MAX_POLL_S = 30;
export const RUN_HEADER = "X-AgentGuard-Run";
export const DECISION_HEADER = "X-AgentGuard-Decision";

type Json = Record<string, unknown>;
export type FetchLike = (input: string, init: RequestInit) => Promise<Response>;
export type FailMode = "closed" | "open";

export interface AgentGuardOptions {
  /** AgentGuard's API, for example `http://localhost:5130`. */
  baseUrl: string;
  clientId: string;
  clientSecret: string;
  /** Signs every request (required when the agent was registered with signed requests). */
  signingSecret?: string;
  /** The default run id for every call (a task or conversation id). */
  runId?: string;
  /** Per-request timeout. Default 10 seconds. */
  timeoutMs?: number;
  /**
   * `closed` (default): any failure to decide denies. `open`: a failure to reach AgentGuard
   * allows, but only while the organisation was last seen in audit mode.
   */
  failMode?: FailMode;
  /** A fetch implementation (default: the global fetch). */
  fetch?: FetchLike;
}

export interface ActionOptions {
  action?: string;
  resource?: string;
  parameters?: Json;
  runId?: string;
  onBehalfOf?: string;
  context?: Json;
  approvalId?: string;
  /** Ask for a single-use decision token the tool can verify. */
  wantToken?: boolean;
}

export interface GuardOptions<A extends unknown[]> {
  tool: string;
  action?: string;
  resource?: string | ((params: Json) => string);
  /** The action's parameters from the call's arguments. Default: the first argument when it
   * is a plain object, otherwise `{ args }`. */
  parameters?: (...args: A) => Json;
  /** Wait for a person when approval is required, then ask again. */
  wait?: boolean;
  waitTimeoutMs?: number;
  wantToken?: boolean;
}

interface TokenState {
  token: string;
  refreshAt: number;
  agent: string;
  agentId: string;
}

const current = new AsyncLocalStorage<Decision>();

/**
 * The decision behind the guarded call that is running (inside a function wrapped with
 * `guard`). A restricted decision carries obligations the function must honour.
 */
export function currentDecision(): Decision | undefined {
  return current.getStore();
}

function checkRunId(runId: string | undefined): string | undefined {
  if (runId !== undefined && !RUN_ID.test(runId)) {
    throw new RangeError("runId is 1 to 128 characters of A-Z a-z 0-9 _ . : @ / -");
  }
  return runId;
}

/** The hex HMAC-SHA256 request signature: `timestamp.nonce.sha256_hex(body)`. */
export function signature(secret: string, timestamp: string, nonce: string, body: string): string {
  const digest = createHash("sha256").update(body, "utf8").digest("hex");
  return createHmac("sha256", secret).update(`${timestamp}.${nonce}.${digest}`).digest("hex");
}

/** The three signed-request headers for one body (a fresh nonce every time). */
export function signHeaders(secret: string, body: string, now = Date.now()): Record<string, string> {
  const timestamp = String(Math.floor(now / 1000));
  const nonce = randomBytes(24).toString("base64url");
  return {
    "X-AgentGuard-Timestamp": timestamp,
    "X-AgentGuard-Nonce": nonce,
    "X-AgentGuard-Signature": signature(secret, timestamp, nonce, body),
  };
}

async function errorFrom(response: Response): Promise<APIError> {
  let body: unknown = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  const data = (body && typeof body === "object" ? body : {}) as Json;
  const err = (data.error && typeof data.error === "object" ? data.error : {}) as Json;
  let code = typeof err.code === "string" ? err.code : "api_error";
  let message = typeof err.message === "string" ? err.message : response.statusText || "error";
  if (data.reason_code === "guard_unavailable") {
    code = "guard_unavailable";
    message = typeof data.reason === "string" ? data.reason : message;
  }
  const details = (err.details && typeof err.details === "object" ? err.details : {}) as Json;
  const Cls = response.status >= 500 ? GuardUnavailable : APIError;
  return new Cls(message, response.status, code, details);
}

function transportError(error: unknown): GuardUnavailable {
  const timeout = error instanceof Error && (error.name === "TimeoutError" || error.name === "AbortError");
  const kind = timeout ? "timeout" : "connection";
  const name = error instanceof Error ? error.name : "Error";
  return new GuardUnavailable(`AgentGuard could not be reached (${kind}: ${name})`, null, "guard_unavailable", {
    transport: kind,
  });
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isPlainObject(value: unknown): value is Json {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const proto: unknown = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/**
 * An agent's connection to AgentGuard. `authorize` asks whether one action may run;
 * `execute` asks AgentGuard to run it (http, MCP and sandbox tools). Every failure to decide
 * is a denial unless `failMode: "open"` and the organisation is in audit mode.
 */
export class AgentGuard {
  readonly baseUrl: string;
  readonly clientId: string;
  readonly runId: string | undefined;
  readonly timeoutMs: number;
  readonly failMode: FailMode;
  readonly #secret: string;
  readonly #signingSecret: string | undefined;
  readonly #fetch: FetchLike;
  #token: TokenState | null = null;
  #pending: Promise<TokenState> | null = null;
  #lastMode: string | null = null;

  constructor(options: AgentGuardOptions) {
    if (!/^https?:\/\//.test(options.baseUrl)) {
      throw new RangeError("baseUrl must be an http(s) URL, for example http://localhost:5130");
    }
    if (!options.clientId || !options.clientSecret) {
      throw new RangeError("clientId and clientSecret are required (from registering the agent)");
    }
    const failMode: string = options.failMode ?? "closed";
    if (failMode !== "closed" && failMode !== "open") {
      throw new RangeError('failMode is "closed" (the default) or "open"');
    }
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.clientId = options.clientId;
    this.#secret = options.clientSecret;
    this.#signingSecret = options.signingSecret;
    this.runId = checkRunId(options.runId);
    this.timeoutMs = options.timeoutMs ?? 10_000;
    this.failMode = failMode;
    this.#fetch = options.fetch ?? ((input, init) => fetch(input, init));
  }

  // Transport

  async #send(path: string, init: RequestInit, timeoutMs = this.timeoutMs): Promise<Response> {
    try {
      return await this.#fetch(`${this.baseUrl}${path}`, {
        ...init,
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (error) {
      throw transportError(error);
    }
  }

  /** A valid agent access token, exchanging the credentials when needed. */
  async accessToken(options: { force?: boolean } = {}): Promise<string> {
    if (!options.force && this.#token && Date.now() < this.#token.refreshAt) return this.#token.token;
    // One exchange at a time, shared by concurrent callers.
    this.#pending ??= this.#exchange().finally(() => {
      this.#pending = null;
    });
    this.#token = await this.#pending;
    return this.#token.token;
  }

  async #exchange(): Promise<TokenState> {
    const response = await this.#send("/oauth/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", "User-Agent": USER_AGENT },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_id: this.clientId,
        client_secret: this.#secret,
      }).toString(),
    });
    if (response.status !== 200) throw await errorFrom(response);
    const data = (await response.json()) as Json;
    const ttl = typeof data.expires_in === "number" ? data.expires_in : 60;
    const margin = Math.min(60, ttl * 0.1);
    return {
      token: String(data.access_token),
      refreshAt: Date.now() + (ttl - margin) * 1000,
      agent: typeof data.agent === "string" ? data.agent : "",
      agentId: typeof data.agent_id === "string" ? data.agent_id : "",
    };
  }

  async #request(
    method: string,
    path: string,
    body?: unknown,
    options: { query?: Record<string, string>; timeoutMs?: number } = {},
  ): Promise<Json> {
    const content = body === undefined ? "" : JSON.stringify(body);
    const query = options.query ? `?${new URLSearchParams(options.query).toString()}` : "";
    for (const attempt of [0, 1]) {
      const headers: Record<string, string> = {
        Authorization: `Bearer ${await this.accessToken({ force: attempt === 1 })}`,
        "User-Agent": USER_AGENT,
      };
      if (body !== undefined) headers["Content-Type"] = "application/json";
      if (this.#signingSecret) Object.assign(headers, signHeaders(this.#signingSecret, content));
      const init: RequestInit = { method, headers };
      if (body !== undefined) init.body = content;
      const response = await this.#send(`${path}${query}`, init, options.timeoutMs);
      if (response.status < 300) {
        const text = await response.text();
        return text ? (JSON.parse(text) as Json) : {};
      }
      const error = await errorFrom(response);
      if (attempt === 0 && response.status === 401 && REFRESH_CODES.has(error.code)) continue;
      throw error;
    }
    /* c8 ignore next */
    throw new Error("unreachable");
  }

  #failed(tool: string, action: string, error: APIError): Decision {
    const detail = { type: error.name, status: error.status, code: error.code, message: error.message };
    const unavailable = error instanceof GuardUnavailable;
    let init: DecisionInit;
    if (unavailable && this.failMode === "open" && this.#lastMode === "audit") {
      init = {
        decision: "allow",
        allowed: true,
        wouldBe: "deny",
        mode: "audit",
        reasonCode: "guard_unavailable",
        reason:
          "AgentGuard could not be reached; allowed because failMode is open and the organisation is in audit mode",
        tool,
        action,
        error: detail,
      };
    } else {
      init = {
        decision: "deny",
        allowed: false,
        wouldBe: "deny",
        reasonCode: unavailable ? "guard_unavailable" : error.code,
        reason: unavailable
          ? "AgentGuard could not decide, so the action is denied"
          : `AgentGuard refused the request: ${error.message}`,
        tool,
        action,
        error: detail,
      };
    }
    return new Decision(init, this.#waiter);
  }

  readonly #waiter = (approvalId: string, timeoutMs: number): Promise<ApprovalStatus> =>
    this.waitForApproval(approvalId, { timeoutMs });

  #body(tool: string, options: ActionOptions, extra: Json = {}): Json {
    const body: Json = {
      tool,
      action: options.action ?? "call",
      parameters: options.parameters ?? {},
      context: options.context ?? {},
      want_token: options.wantToken ?? false,
      ...extra,
    };
    if (options.resource !== undefined) body.resource = options.resource;
    const run = checkRunId(options.runId ?? this.runId);
    if (run !== undefined) body.run_id = run;
    if (options.onBehalfOf !== undefined) body.on_behalf_of = options.onBehalfOf;
    if (options.approvalId !== undefined) body.approval_id = options.approvalId;
    return body;
  }

  async #decide(path: string, body: Json, tool: string, action: string): Promise<Decision> {
    let data: Json;
    try {
      data = await this.#request("POST", path, body);
    } catch (error) {
      if (error instanceof APIError) return this.#failed(tool, action, error);
      throw error;
    }
    this.#lastMode = typeof data.mode === "string" ? data.mode : null;
    return Decision.fromApi(data, tool, action, this.#waiter);
  }

  // Decisions

  /** Decide one action. Never rejects for a failure to decide: it resolves to a denial. */
  authorize(tool: string, options: ActionOptions = {}): Promise<Decision> {
    return this.#decide("/api/v1/authorize", this.#body(tool, options), tool, options.action ?? "call");
  }

  /** Decide one action and, when allowed, have AgentGuard run it (`decision.result`). */
  execute(tool: string, options: Omit<ActionOptions, "wantToken"> = {}): Promise<Decision> {
    return this.#decide("/api/v1/execute", this.#body(tool, options), tool, options.action ?? "call");
  }

  /** Ask a person before acting, even where policy would allow the action. */
  askPerson(tool: string, options: Omit<ActionOptions, "approvalId" | "wantToken"> & { reason?: string } = {}) {
    const body = this.#body(tool, options, { reason: options.reason ?? "" });
    return this.#decide("/api/v1/approvals", body, tool, options.action ?? "call");
  }

  // Approvals

  /** The approval's status; `wait` long-polls up to 30 seconds for a change. */
  async approvalStatus(approvalId: string, options: { wait?: number } = {}): Promise<ApprovalStatus> {
    const wait = Math.max(0, Math.min(MAX_POLL_S, Math.floor(options.wait ?? 0)));
    const data = await this.#request("GET", `/api/v1/approvals/${encodeURIComponent(approvalId)}/status`, undefined, {
      query: { wait: String(wait) },
      timeoutMs: this.timeoutMs + wait * 1000,
    });
    return ApprovalStatus.fromApi(data);
  }

  /** Wait until the approval is decided or `timeoutMs` passes (then still `pending`). */
  async waitForApproval(approvalId: string, options: { timeoutMs?: number } = {}): Promise<ApprovalStatus> {
    const deadline = Date.now() + (options.timeoutMs ?? 300_000);
    const pollWait = () => Math.max(0, Math.min(MAX_POLL_S, Math.floor((deadline - Date.now()) / 1000)));
    for (;;) {
      const status = await this.approvalStatus(approvalId, { wait: pollWait() });
      if (!status.pending || Date.now() >= deadline) return status;
      if (pollWait() === 0) await sleep(Math.max(0, Math.min(1000, deadline - Date.now())));
    }
  }

  // Content, runs, identity

  /** Scan untrusted content the agent read. Rejects with `GuardUnavailable` when the scan
   * cannot run: treat the content as untrusted then. */
  async scan(content: string, options: { source?: string; spotlight?: boolean; runId?: string } = {}): Promise<ScanResult> {
    const body: Json = { content, source: options.source ?? "unknown", spotlight: options.spotlight ?? false };
    const run = checkRunId(options.runId ?? this.runId);
    if (run !== undefined) body.run_id = run;
    return scanResult(await this.#request("POST", "/api/v1/content/scan", body));
  }

  /** Mark the run finished. True when it was open. */
  async endRun(runId?: string): Promise<boolean> {
    const run = checkRunId(runId ?? this.runId);
    if (run === undefined) throw new RangeError("No runId: pass one or set it on the client");
    const data = await this.#request("POST", `/api/v1/runs/${encodeURIComponent(run)}/end`, {});
    return data.ended === true;
  }

  /** The agent these credentials belong to. */
  async me(): Promise<AgentIdentity> {
    return agentIdentity(await this.#request("GET", "/api/v1/agent/me"));
  }

  /** The MCP gateway URL and headers (with a current token) for any MCP client. */
  async mcpSettings(runId?: string): Promise<{ url: string; headers: Record<string, string> }> {
    const headers: Record<string, string> = { Authorization: `Bearer ${await this.accessToken()}` };
    const run = checkRunId(runId ?? this.runId);
    if (run !== undefined) headers[RUN_HEADER] = run;
    return { url: `${this.baseUrl}/mcp`, headers };
  }

  // The wrapper

  /**
   * Wrap a function so every call is authorized first. Denied rejects with `ActionDenied`;
   * needing approval rejects with `ApprovalRequired` (with `wait: true` it waits for the
   * person, asks again and runs only if now allowed). Inside the function,
   * `currentDecision()` returns the decision (for obligations).
   */
  guard<A extends unknown[], R>(
    fn: (...args: A) => R | Promise<R>,
    options: GuardOptions<A>,
  ): (...args: A) => Promise<R> {
    const action = options.action ?? "call";
    return async (...args: A): Promise<R> => {
      const first = args[0];
      const params = options.parameters
        ? options.parameters(...args)
        : args.length === 1 && isPlainObject(first)
          ? first
          : { args };
      const resource = typeof options.resource === "function" ? options.resource(params) : options.resource;
      const base: ActionOptions = { action, parameters: params, wantToken: options.wantToken ?? false };
      if (resource !== undefined) base.resource = resource;
      let decision = await this.authorize(options.tool, base);
      if (decision.needsApproval && options.wait && decision.approval) {
        const status = await decision.waitForApproval(options.waitTimeoutMs ?? 300_000);
        if (status.pending) throw new ApprovalRequired(decision);
        decision = await this.authorize(options.tool, { ...base, approvalId: decision.approval.id });
      }
      decision.raiseForDecision();
      return await current.run(decision, () => fn(...args));
    };
  }
}
