/**
 * Errors the SDK throws. `authorize`, `execute` and `askPerson` never throw for a failure to
 * decide: they resolve to a denied `Decision` (fail closed). These are for code that wants
 * an exception (`raiseForDecision`, `guard`), for calls with no decision to return, and for
 * resource-side verification.
 */

import type { Decision, ApprovalInfo } from "./models.js";

export class AgentGuardError extends Error {
  override name = "AgentGuardError";
}

/** AgentGuard answered with an error (`{ error: { code, message, details } }`). */
export class APIError extends AgentGuardError {
  override name = "APIError";
  constructor(
    message: string,
    readonly status: number | null,
    readonly code: string,
    readonly details: Record<string, unknown> = {},
  ) {
    super(message);
  }
}

/** AgentGuard could not be reached or could not decide (network error, timeout, 5xx). */
export class GuardUnavailable extends APIError {
  override name = "GuardUnavailable";
}

/** The action was not allowed. `decision` explains why. */
export class ActionDenied extends AgentGuardError {
  override name = "ActionDenied";
  constructor(readonly decision: Decision) {
    super(`${decision.tool}.${decision.action} denied: ${decision.reason}`);
  }
  get reasonCode(): string {
    return this.decision.reasonCode;
  }
}

/**
 * The action waits for a person. A subclass of `ActionDenied` because, until a person
 * approves, the action must not run.
 */
export class ApprovalRequired extends ActionDenied {
  override name = "ApprovalRequired";
  constructor(decision: Decision) {
    super(decision);
    this.message = `${decision.tool}.${decision.action} needs approval: ${decision.reason}${
      decision.approval ? ` (approval ${decision.approval.id})` : ""
    }`;
  }
  get approval(): ApprovalInfo | null {
    return this.decision.approval;
  }
}

export type RejectReason =
  | "missing_token"
  | "malformed"
  | "invalid_or_expired"
  | "unknown_key"
  | "wrong_org"
  | "wrong_agent"
  | "tool_mismatch"
  | "action_mismatch"
  | "resource_mismatch"
  | "params_mismatch"
  | "already_used"
  | "guard_unavailable";

/** A decision token failed verification on the resource side. */
export class DecisionRejected extends AgentGuardError {
  override name = "DecisionRejected";
  constructor(
    readonly reason: RejectReason,
    message: string,
  ) {
    super(message);
  }
}
