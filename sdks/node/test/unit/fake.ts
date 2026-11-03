/** A fake fetch: routes by method and path, records every request. */

import { randomUUID } from "node:crypto";

import { SignJWT, exportJWK, generateKeyPair, type JWK } from "jose";

import { actionHash } from "../../src/index.js";

export const BASE = "http://agentguard.test";
export const ORG = "83bf425d-2fe8-4a56-8845-70ba8ea89211";
export const AGENT = "1851cc95-2f4b-41ef-a78f-872411cf1add";

export interface Recorded {
  method: string;
  path: string;
  query: URLSearchParams;
  headers: Record<string, string>;
  body: string;
}

type Handler = (req: Recorded) => Response | Promise<Response>;

export class FakeApi {
  calls: Recorded[] = [];
  routes = new Map<string, Handler[]>();

  on(method: string, path: string, ...handlers: Handler[]): this {
    this.routes.set(`${method} ${path}`, handlers);
    return this;
  }

  count(method: string, path: string): number {
    return this.calls.filter((c) => c.method === method && c.path === path).length;
  }

  last(method: string, path: string): Recorded {
    return this.calls.filter((c) => c.method === method && c.path === path).at(-1)!;
  }

  fetch = async (input: string, init: RequestInit): Promise<Response> => {
    const url = new URL(input);
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries((init.headers ?? {}) as Record<string, string>)) headers[k.toLowerCase()] = v;
    const req: Recorded = {
      method: init.method ?? "GET",
      path: url.pathname,
      query: url.searchParams,
      headers,
      body: typeof init.body === "string" ? init.body : "",
    };
    this.calls.push(req);
    const handlers = this.routes.get(`${req.method} ${req.path}`);
    if (!handlers?.length) return json(404, { error: { code: "not_found", message: req.path } });
    const handler = handlers.length > 1 ? handlers.shift()! : handlers[0]!;
    return handler(req);
  };
}

export function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

export function tokenResponse(token = "agent-token-1", ttl = 900): Response {
  return json(200, { access_token: token, token_type: "Bearer", expires_in: ttl, agent: "bot", agent_id: AGENT });
}

export function decision(value = "allow", extra: Record<string, unknown> = {}): Record<string, unknown> {
  const body: Record<string, unknown> = {
    decision_id: randomUUID(),
    decision: value,
    allowed: value === "allow" || value === "restrict",
    would_be: value,
    mode: "enforce",
    reason_code: value === "allow" ? "permission" : value === "deny" ? "policy_deny" : value,
    reason: `because ${value}`,
    reasons: [],
    policy_id: null,
    policy: null,
    policy_version: null,
    obligations: {},
    risk: { level: "low", score: 10 },
    data_classes: [],
    action_hash: "a".repeat(64),
    approval: null,
    decision_token: null,
    expires_at: null,
    run_id: null,
  };
  if (value === "require_approval") {
    body.approval = {
      id: randomUUID(),
      status: "pending",
      expires_at: "2026-11-02T13:30:06Z",
      url: "http://localhost:5110/approvals/x",
      required: [{ count: 1, roles: ["org_admin"] }],
    };
  }
  return { ...body, ...extra };
}

export function approvalStatus(status: string, id = "ap-1"): Record<string, unknown> {
  return {
    id,
    status,
    comment: status === "pending" ? null : "fine",
    expires_at: "2026-11-02T13:30:06Z",
    decided_at: status === "pending" ? null : "2026-11-02T12:31:00Z",
    result: null,
  };
}

type PrivateKey = Awaited<ReturnType<typeof generateKeyPair>>["privateKey"];

function missing(): never {
  throw new Error("call init() first");
}

export class Signer {
  kid: string;
  #key: PrivateKey | null = null;
  #jwk: JWK | null = null;

  constructor(kid = "kid-1") {
    this.kid = kid;
  }

  async init(): Promise<this> {
    const { privateKey, publicKey } = await generateKeyPair("EdDSA", { crv: "Ed25519", extractable: true });
    this.#key = privateKey;
    this.#jwk = { ...(await exportJWK(publicKey)), kid: this.kid, alg: "EdDSA", use: "sig" };
    return this;
  }

  jwk(): JWK {
    return this.#jwk!;
  }

  async token(options: {
    tool?: string; action?: string; resource?: string; params?: Record<string, unknown>;
    org?: string; agent?: string; issuer?: string; audience?: string; typ?: string; ttl?: number;
    claims?: Record<string, unknown>;
  } = {}): Promise<string> {
    const tool = options.tool ?? "refunds";
    const action = options.action ?? "create";
    const resource = options.resource ?? "customer:c1";
    const org = options.org ?? ORG;
    const agent = options.agent ?? AGENT;
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({
      org, agent: "bot", did: randomUUID(), tool, act: action, res: resource,
      ah: actionHash(org, agent, tool, action, resource, options.params ?? {}), obl: {},
      ...options.claims,
    })
      .setProtectedHeader({ alg: "EdDSA", kid: this.kid, typ: options.typ ?? "agd+jwt" })
      .setIssuer(options.issuer ?? BASE)
      .setAudience(options.audience ?? "agentguard-decision")
      .setSubject(agent)
      .setIssuedAt(now)
      .setExpirationTime(now + (options.ttl ?? 60))
      .setJti(randomUUID().replaceAll("-", ""))
      .sign(this.#key ?? missing());
  }
}
