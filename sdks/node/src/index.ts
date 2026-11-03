/**
 * Euron Open AgentGuard for Node.js.
 *
 * Agent side: `new AgentGuard({ baseUrl, clientId, clientSecret }).authorize(tool, {...})`.
 * Tool side: `new DecisionVerifier({ baseUrl, apiKey }).verify(token, {...})`.
 * Express middleware: `@euron/agentguard/express`.
 */

export { ACTION_HASH_PREFIX, actionHash, canonicalJson, compareCodePoints, formatFloat } from "./canonical.js";
export {
  AgentGuard,
  DECISION_HEADER,
  RUN_HEADER,
  VERSION,
  currentDecision,
  signHeaders,
  signature,
  type ActionOptions,
  type AgentGuardOptions,
  type FailMode,
  type FetchLike,
  type GuardOptions,
} from "./client.js";
export {
  APIError,
  ActionDenied,
  AgentGuardError,
  ApprovalRequired,
  DecisionRejected,
  GuardUnavailable,
  type RejectReason,
} from "./errors.js";
export {
  ApprovalStatus,
  Decision,
  type AgentIdentity,
  type ApprovalInfo,
  type DecisionValue,
  type ScanResult,
  type VerifiedDecision,
} from "./models.js";
export { DECISION_AUDIENCE, DECISION_TYP, DecisionVerifier, type VerifierOptions, type VerifyOptions } from "./verify.js";
