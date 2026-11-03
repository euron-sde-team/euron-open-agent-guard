/**
 * Express (and any connect-style framework): protect your own tool route with
 * decision-token verification.
 *
 *     app.post("/refunds", express.json(), requireDecision(verifier, { tool: "refunds", action: "create" }), handler);
 *
 * The agent sends the token from `authorize(..., { wantToken: true })` in the
 * `X-AgentGuard-Decision` header. The parameters are `req.body` (parse JSON first) or, when
 * there is no body, `req.query`. A missing token answers 401, any failed check 403 and
 * AgentGuard being unreachable 503; the handler never runs in those cases. The verified
 * decision is on `res.locals.agentguardDecision`.
 *
 * Express is not a dependency: the types below are the few members the middleware uses.
 */

import { DECISION_HEADER } from "./client.js";
import { DecisionRejected } from "./errors.js";
import type { VerifiedDecision } from "./models.js";
import type { DecisionVerifier } from "./verify.js";

export interface RequestLike {
  body?: unknown;
  query?: unknown;
  get?(name: string): string | undefined;
  headers: Record<string, string | string[] | undefined>;
}

export interface ResponseLike {
  locals: Record<string, unknown>;
  status(code: number): ResponseLike;
  set?(name: string, value: string): unknown;
  json(body: unknown): unknown;
}

export type NextLike = (error?: unknown) => void;

export interface RequireDecisionOptions<Req extends RequestLike> {
  tool: string;
  action?: string;
  /** Pin the resource key, as a string or computed from the request and parameters. */
  resource?: string | ((req: Req, params: Record<string, unknown>) => string);
  /** How the action's parameters are read from the request (default: body, then query). */
  parameters?: (req: Req) => Record<string, unknown>;
  agentId?: string;
  header?: string;
}

function plain(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function statusFor(reason: string): number {
  if (reason === "missing_token") return 401;
  if (reason === "guard_unavailable") return 503;
  return 403;
}

/** Middleware that verifies the request's decision token for this action. */
export function requireDecision<Req extends RequestLike = RequestLike>(
  verifier: DecisionVerifier,
  options: RequireDecisionOptions<Req>,
): (req: Req, res: ResponseLike, next: NextLike) => Promise<void> {
  const header = (options.header ?? DECISION_HEADER).toLowerCase();
  return async (req, res, next) => {
    let params: Record<string, unknown>;
    if (options.parameters) {
      params = options.parameters(req);
    } else {
      const body = plain(req.body);
      params = body && Object.keys(body).length > 0 ? body : (plain(req.query) ?? {});
    }
    const raw = req.headers[header];
    const token = Array.isArray(raw) ? raw[0] : raw;
    const resource = typeof options.resource === "function" ? options.resource(req, params) : options.resource;
    try {
      const verifyOptions: Parameters<DecisionVerifier["verify"]>[1] = {
        tool: options.tool,
        action: options.action ?? "call",
        parameters: params,
      };
      if (resource !== undefined) verifyOptions.resource = resource;
      if (options.agentId !== undefined) verifyOptions.agentId = options.agentId;
      const decision: VerifiedDecision = await verifier.verify(token, verifyOptions);
      res.locals.agentguardDecision = decision;
      next();
    } catch (error) {
      if (error instanceof DecisionRejected) {
        if (error.reason === "missing_token") res.set?.("WWW-Authenticate", "AgentGuard-Decision");
        res.status(statusFor(error.reason)).json({ error: { code: error.reason, message: error.message } });
        return;
      }
      next(error);
    }
  };
}
