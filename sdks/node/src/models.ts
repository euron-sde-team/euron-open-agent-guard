/** The typed results of the agent runtime API (see docs/api/openapi.yaml). */

import { ActionDenied, ApprovalRequired } from "./errors.js";

export type DecisionValue = "allow" | "deny" | "require_approval" | "restrict" | "quarantine";
const DECISIONS: readonly string[] = ["allow", "deny", "require_approval", "restrict", "quarantine"];
const FINAL = new Set([
  "approved",
  "rejected",
  "changes_requested",
  "expired",
  "revoked",
  "executed",
  "failed",
]);

type Json = Record<string, unknown>;

function str(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : fallback;
}

function strOrNull(value: unknown): string | null {
  return typeof value === "string" && value ? value : null;
}

function obj(value: unknown): Json {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Json) : {};
}

function list<T = unknown>(value: unknown): T[] {
  return Array.isArray(value) ? (value as T[]) : [];
}

function date(value: unknown): Date | null {
  if (typeof value !== "string" || !value) return null;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

/** The approval request a `require_approval` decision created (or found). */
export interface ApprovalInfo {
  id: string;
  status: string;
  expiresAt: Date | null;
  url: string;
  required: Json[];
  comment: string | null;
}

export function approvalInfo(data: Json): ApprovalInfo {
  return {
    id: str(data.id),
    status: str(data.status, "pending"),
    expiresAt: date(data.expires_at),
    url: str(data.url),
    required: list<Json>(data.required),
    comment: strOrNull(data.comment),
  };
}

/** Where an approval request stands. */
export class ApprovalStatus {
  constructor(
    readonly id: string,
    readonly status: string,
    readonly comment: string | null,
    readonly expiresAt: Date | null,
    readonly decidedAt: Date | null,
    readonly result: Json | null,
  ) {}

  get approved(): boolean {
    return this.status === "approved";
  }
  get pending(): boolean {
    return this.status === "pending";
  }
  get final(): boolean {
    return FINAL.has(this.status);
  }

  static fromApi(data: Json): ApprovalStatus {
    return new ApprovalStatus(
      str(data.id),
      str(data.status, "pending"),
      strOrNull(data.comment),
      date(data.expires_at),
      date(data.decided_at),
      data.result && typeof data.result === "object" ? (data.result as Json) : null,
    );
  }
}

export interface DecisionInit {
  decision: DecisionValue;
  allowed: boolean;
  reasonCode: string;
  reason: string;
  tool: string;
  action: string;
  decisionId?: string | null;
  wouldBe?: DecisionValue;
  mode?: "enforce" | "audit";
  reasons?: unknown[];
  policyId?: string | null;
  policy?: string | null;
  policyVersion?: number | null;
  obligations?: Json;
  risk?: Json;
  dataClasses?: string[];
  actionHash?: string | null;
  approval?: ApprovalInfo | null;
  decisionToken?: string | null;
  expiresAt?: Date | null;
  runId?: string | null;
  executed?: boolean;
  result?: unknown;
  resultMeta?: Json;
  error?: Json | null;
  raw?: Json;
}

export type Waiter = (approvalId: string, timeoutMs: number) => Promise<ApprovalStatus>;

/**
 * One decision. `allowed` is the only field that says whether to act. A decision the SDK
 * made itself because AgentGuard could not be asked (fail closed) has `decisionId` null,
 * `reasonCode` `guard_unavailable` (or the API's error code) and the failure in `error`.
 */
export class Decision {
  readonly decision: DecisionValue;
  readonly allowed: boolean;
  readonly reasonCode: string;
  readonly reason: string;
  readonly tool: string;
  readonly action: string;
  readonly decisionId: string | null;
  readonly wouldBe: DecisionValue;
  readonly mode: "enforce" | "audit";
  readonly reasons: unknown[];
  readonly policyId: string | null;
  readonly policy: string | null;
  readonly policyVersion: number | null;
  readonly obligations: Json;
  readonly risk: Json;
  readonly dataClasses: string[];
  readonly actionHash: string | null;
  readonly approval: ApprovalInfo | null;
  readonly decisionToken: string | null;
  readonly expiresAt: Date | null;
  readonly runId: string | null;
  readonly executed: boolean;
  readonly result: unknown;
  readonly resultMeta: Json;
  readonly error: Json | null;
  readonly raw: Json;
  readonly #waiter: Waiter | null;

  constructor(init: DecisionInit, waiter: Waiter | null = null) {
    this.decision = init.decision;
    this.allowed = init.allowed;
    this.reasonCode = init.reasonCode;
    this.reason = init.reason;
    this.tool = init.tool;
    this.action = init.action;
    this.decisionId = init.decisionId ?? null;
    this.wouldBe = init.wouldBe ?? init.decision;
    this.mode = init.mode ?? "enforce";
    this.reasons = init.reasons ?? [];
    this.policyId = init.policyId ?? null;
    this.policy = init.policy ?? null;
    this.policyVersion = init.policyVersion ?? null;
    this.obligations = init.obligations ?? {};
    this.risk = init.risk ?? {};
    this.dataClasses = init.dataClasses ?? [];
    this.actionHash = init.actionHash ?? null;
    this.approval = init.approval ?? null;
    this.decisionToken = init.decisionToken ?? null;
    this.expiresAt = init.expiresAt ?? null;
    this.runId = init.runId ?? null;
    this.executed = init.executed ?? false;
    this.result = init.result ?? null;
    this.resultMeta = init.resultMeta ?? {};
    this.error = init.error ?? null;
    this.raw = init.raw ?? {};
    this.#waiter = waiter;
  }

  /** A person must approve before this exact action may run. */
  get needsApproval(): boolean {
    return this.decision === "require_approval";
  }
  get denied(): boolean {
    return !this.allowed;
  }
  /** Allowed, with obligations (row limits, redactions) the tool must honour. */
  get restricted(): boolean {
    return this.allowed && this.decision === "restrict";
  }
  /** The SDK denied because AgentGuard could not be asked or answered with an error. */
  get failedClosed(): boolean {
    return this.error !== null;
  }

  /** Return this decision when allowed; throw `ApprovalRequired` or `ActionDenied`. */
  raiseForDecision(): this {
    if (this.allowed) return this;
    if (this.needsApproval) throw new ApprovalRequired(this);
    throw new ActionDenied(this);
  }

  /** Wait until a person decides the approval (or `timeoutMs` passes; then still pending). */
  async waitForApproval(timeoutMs = 300_000): Promise<ApprovalStatus> {
    if (!this.approval || !this.#waiter) throw new Error("This decision has no approval to wait for");
    return this.#waiter(this.approval.id, timeoutMs);
  }

  static fromApi(data: Json, tool: string, action: string, waiter: Waiter | null): Decision {
    const raw = typeof data.decision === "string" ? data.decision : "";
    const decision = (DECISIONS.includes(raw) ? raw : "deny") as DecisionValue;
    const wouldBe = typeof data.would_be === "string" && DECISIONS.includes(data.would_be)
      ? (data.would_be as DecisionValue)
      : decision;
    const approval = data.approval && typeof data.approval === "object"
      ? approvalInfo(data.approval as Json)
      : null;
    return new Decision(
      {
        decision,
        allowed: data.allowed === true && (decision === "allow" || decision === "restrict"),
        reasonCode: str(data.reason_code, "unknown"),
        reason: str(data.reason),
        tool,
        action,
        decisionId: strOrNull(data.decision_id),
        wouldBe,
        mode: data.mode === "audit" ? "audit" : "enforce",
        reasons: list(data.reasons),
        policyId: strOrNull(data.policy_id),
        policy: strOrNull(data.policy),
        policyVersion: typeof data.policy_version === "number" ? data.policy_version : null,
        obligations: obj(data.obligations),
        risk: obj(data.risk),
        dataClasses: list<string>(data.data_classes),
        actionHash: strOrNull(data.action_hash),
        approval,
        decisionToken: strOrNull(data.decision_token),
        expiresAt: date(data.expires_at),
        runId: strOrNull(data.run_id),
        executed: data.executed === true,
        result: data.result ?? null,
        resultMeta: obj(data.result_meta),
        raw: data,
      },
      waiter,
    );
  }
}

/** The verdict on untrusted content. */
export interface ScanResult {
  verdict: "none" | "suspicious" | "injection";
  score: number;
  signals: Json[];
  dataClasses: string[];
  findings: Json[];
  taintedRun: boolean;
  content: string | null;
  raw: Json;
}

export function scanResult(data: Json): ScanResult {
  const verdict = data.verdict === "none" || data.verdict === "injection" ? data.verdict : "suspicious";
  return {
    verdict,
    score: typeof data.score === "number" ? data.score : 0,
    signals: list<Json>(data.signals),
    dataClasses: list<string>(data.data_classes),
    findings: list<Json>(data.findings),
    taintedRun: data.tainted_run === true,
    content: strOrNull(data.content),
    raw: data,
  };
}

/** Who the credentials belong to. */
export interface AgentIdentity {
  agentId: string;
  agent: string;
  name: string;
  orgId: string;
  project: string;
  status: string;
  roles: string[];
}

export function agentIdentity(data: Json): AgentIdentity {
  return {
    agentId: str(data.agent_id),
    agent: str(data.agent),
    name: str(data.name),
    orgId: str(data.org_id),
    project: str(data.project),
    status: str(data.status),
    roles: list<string>(data.roles),
  };
}

/** A decision token that passed every check on the resource side. */
export interface VerifiedDecision {
  decisionId: string;
  orgId: string;
  agentId: string;
  agent: string;
  tool: string;
  action: string;
  resource: string;
  actionHash: string;
  obligations: Json;
  expiresAt: Date | null;
  tokenId: string;
  /** False in offline mode: the token was not used up and could be presented again. */
  redeemed: boolean;
}
