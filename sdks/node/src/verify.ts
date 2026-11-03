/**
 * Resource-side verification of decision tokens: the check that makes a client-side
 * `authorize` binding. A tool that acts only on a verified token cannot be called by an
 * agent that skipped AgentGuard.
 *
 * Checks, in order: the Ed25519 signature against AgentGuard's JWKS (cached, refreshed when
 * a token names an unknown key, at most every `minRefreshMs`); type, audience, issuer and
 * expiry; organisation, tool and action (and resource and agent when pinned); the action hash
 * recomputed locally from the parameters about to be used; and, online (the default), a
 * redemption at AgentGuard that uses the token up, so a second presentation fails.
 *
 * Offline mode skips the redemption: every other check holds, but the token is NOT single
 * use and can be replayed until it expires (60 seconds by default).
 */

import { timingSafeEqual } from "node:crypto";

import { type CryptoKey, type JWK, type JWTPayload, decodeProtectedHeader, errors, importJWK, jwtVerify } from "jose";

import { actionHash } from "./canonical.js";
import type { FetchLike } from "./client.js";
import { DecisionRejected, type RejectReason } from "./errors.js";
import type { VerifiedDecision } from "./models.js";

export const DECISION_TYP = "agd+jwt";
export const DECISION_AUDIENCE = "agentguard-decision";
const REDEEM_REASONS: Record<string, RejectReason> = {
  invalid_or_expired: "invalid_or_expired",
  action_mismatch: "params_mismatch",
  already_used: "already_used",
};

type Json = Record<string, unknown>;

export interface VerifierOptions {
  baseUrl: string;
  /** A management API key (`agk_...`, read scope is enough). Required online. */
  apiKey?: string;
  /** The organisation tokens must belong to. Default: the API key's organisation. */
  orgId?: string;
  /** Expected issuer (AgentGuard's PUBLIC_API_URL). Default: `baseUrl`. */
  issuer?: string;
  /** Skip redemption (NOT single use; see the module comment). */
  offline?: boolean;
  jwksTtlMs?: number;
  minRefreshMs?: number;
  leewaySeconds?: number;
  timeoutMs?: number;
  fetch?: FetchLike;
}

export interface VerifyOptions {
  tool: string;
  action?: string;
  /** Pin the resource key. Undefined accepts the token's (derived from the parameters). */
  resource?: string;
  parameters?: Record<string, unknown>;
  orgId?: string;
  agentId?: string;
}

function equal(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

/** Verify decision tokens before a tool acts. */
export class DecisionVerifier {
  readonly baseUrl: string;
  readonly issuer: string;
  readonly offline: boolean;
  orgId: string | undefined;
  minRefreshMs: number;
  readonly #apiKey: string | undefined;
  readonly #jwksTtlMs: number;
  readonly #leeway: number;
  readonly #timeoutMs: number;
  readonly #fetch: FetchLike;
  #keys = new Map<string, CryptoKey | Uint8Array>();
  #fetchedAt = 0;
  #loading: Promise<void> | null = null;

  constructor(options: VerifierOptions) {
    if (!/^https?:\/\//.test(options.baseUrl)) throw new RangeError("baseUrl must be an http(s) URL");
    const offline = options.offline ?? false;
    if (!offline && !options.apiKey) {
      throw new RangeError("Online verification needs a management API key (agk_...)");
    }
    if (offline && !options.apiKey && !options.orgId) {
      throw new RangeError("Offline verification needs orgId (or an API key to look it up)");
    }
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.issuer = (options.issuer ?? this.baseUrl).replace(/\/+$/, "");
    this.offline = offline;
    this.orgId = options.orgId;
    this.#apiKey = options.apiKey;
    this.#jwksTtlMs = options.jwksTtlMs ?? 300_000;
    this.minRefreshMs = options.minRefreshMs ?? 10_000;
    this.#leeway = options.leewaySeconds ?? 5;
    this.#timeoutMs = options.timeoutMs ?? 5_000;
    this.#fetch = options.fetch ?? ((input, init) => fetch(input, init));
  }

  #headers(): Record<string, string> {
    const headers: Record<string, string> = { "User-Agent": "euron-agentguard-node" };
    if (this.#apiKey) headers.Authorization = `Bearer ${this.#apiKey}`;
    return headers;
  }

  async #call(path: string, init: RequestInit = {}): Promise<Response> {
    try {
      return await this.#fetch(`${this.baseUrl}${path}`, {
        ...init,
        headers: { ...this.#headers(), ...(init.headers as Record<string, string> | undefined) },
        signal: AbortSignal.timeout(this.#timeoutMs),
      });
    } catch (error) {
      const name = error instanceof Error ? error.name : "Error";
      throw new DecisionRejected("guard_unavailable", `AgentGuard could not be reached (${name})`);
    }
  }

  async #get(path: string): Promise<Json> {
    const response = await this.#call(path);
    if (response.status !== 200) {
      throw new DecisionRejected("guard_unavailable", `${path} answered ${response.status}`);
    }
    return (await response.json()) as Json;
  }

  async #load(): Promise<void> {
    const data = await this.#get("/.well-known/jwks.json");
    const keys = new Map<string, CryptoKey | Uint8Array>();
    for (const entry of Array.isArray(data.keys) ? (data.keys as unknown[]) : []) {
      if (!entry || typeof entry !== "object") continue;
      const jwk = entry as JWK;
      if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || !jwk.kid) continue;
      keys.set(jwk.kid, await importJWK({ ...jwk, alg: "EdDSA" }, "EdDSA"));
    }
    this.#keys = keys;
    this.#fetchedAt = Date.now();
  }

  async #key(kid: string): Promise<CryptoKey | Uint8Array> {
    const stale = this.#keys.size === 0 || Date.now() - this.#fetchedAt > this.#jwksTtlMs;
    const unknown = !this.#keys.has(kid) && Date.now() - this.#fetchedAt >= this.minRefreshMs;
    if (stale || unknown) {
      this.#loading ??= this.#load().finally(() => {
        this.#loading = null;
      });
      await this.#loading;
    }
    const key = this.#keys.get(kid);
    if (!key) throw new DecisionRejected("unknown_key", "The token is signed with an unknown key");
    return key;
  }

  /** The organisation tokens must belong to (looked up from the API key once). */
  async resolveOrgId(): Promise<string> {
    this.orgId ??= String((await this.#get("/api/v1/org")).id);
    return this.orgId;
  }

  /**
   * Verify (and, online, use up) a decision token for this exact action. Rejects with
   * `DecisionRejected` on any failure, including AgentGuard being down online (fail closed).
   */
  async verify(token: string | null | undefined, options: VerifyOptions): Promise<VerifiedDecision> {
    if (!token) throw new DecisionRejected("missing_token", "No decision token was presented");
    let header;
    try {
      header = decodeProtectedHeader(token);
    } catch {
      throw new DecisionRejected("malformed", "The decision token is not a JWT");
    }
    if (header.typ !== DECISION_TYP || header.alg !== "EdDSA") {
      throw new DecisionRejected("malformed", "This is not an AgentGuard decision token");
    }
    if (typeof header.kid !== "string" || !header.kid) {
      throw new DecisionRejected("malformed", "The decision token names no signing key");
    }
    const key = await this.#key(header.kid);
    let claims: JWTPayload;
    try {
      ({ payload: claims } = await jwtVerify(token, key, {
        algorithms: ["EdDSA"],
        audience: DECISION_AUDIENCE,
        issuer: this.issuer,
        typ: DECISION_TYP,
        clockTolerance: this.#leeway,
        requiredClaims: ["exp", "iat", "jti", "sub", "aud", "iss"],
      }));
    } catch (error) {
      const message = error instanceof errors.JWTExpired ? "The decision token expired" : "The decision token is not valid";
      throw new DecisionRejected("invalid_or_expired", message);
    }
    const action = options.action ?? "call";
    const orgId = options.orgId ?? (await this.resolveOrgId());
    const subject = String(claims.sub);
    if (String(claims.org) !== orgId) throw new DecisionRejected("wrong_org", "The token was issued to another organisation");
    if (options.agentId !== undefined && subject !== options.agentId) {
      throw new DecisionRejected("wrong_agent", "The token was issued to another agent");
    }
    if (claims.tool !== options.tool) throw new DecisionRejected("tool_mismatch", `The token is for ${String(claims.tool)}`);
    if (claims.act !== action) throw new DecisionRejected("action_mismatch", `The token is for action ${String(claims.act)}`);
    const resource = typeof claims.res === "string" ? claims.res : "";
    if (options.resource !== undefined && options.resource !== resource) {
      throw new DecisionRejected("resource_mismatch", "The token is for another resource");
    }
    let computed: string;
    try {
      computed = actionHash(orgId, subject, options.tool, action, resource, options.parameters ?? {});
    } catch (error) {
      throw new DecisionRejected("params_mismatch", `The parameters cannot be hashed: ${String(error)}`);
    }
    if (!equal(computed, typeof claims.ah === "string" ? claims.ah : "")) {
      throw new DecisionRejected("params_mismatch", "The token was issued for different parameters");
    }
    const result: VerifiedDecision = {
      decisionId: typeof claims.did === "string" ? claims.did : "",
      orgId: String(claims.org),
      agentId: subject,
      agent: typeof claims.agent === "string" ? claims.agent : "",
      tool: options.tool,
      action,
      resource,
      actionHash: computed,
      obligations: claims.obl && typeof claims.obl === "object" ? (claims.obl as Json) : {},
      expiresAt: typeof claims.exp === "number" ? new Date(claims.exp * 1000) : null,
      tokenId: String(claims.jti),
      redeemed: false,
    };
    if (this.offline) return result;
    const response = await this.#call("/api/v1/decisions/redeem", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token, action_hash: computed }),
    });
    if (response.status !== 200) {
      throw new DecisionRejected(
        "guard_unavailable",
        `AgentGuard refused or failed the redemption (${response.status}): check the verifier's API key`,
      );
    }
    const data = (await response.json()) as Json;
    if (data.valid !== true) {
      const reason = typeof data.reason === "string" ? data.reason : "invalid_or_expired";
      throw new DecisionRejected(REDEEM_REASONS[reason] ?? "invalid_or_expired", `AgentGuard did not redeem the token: ${reason}`);
    }
    return { ...result, redeemed: true };
  }
}
