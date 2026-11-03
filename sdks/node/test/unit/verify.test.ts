import { beforeEach, describe, expect, it } from "vitest";

import { requireDecision, type ResponseLike } from "../../src/express.js";
import { DecisionRejected, DecisionVerifier, type VerifiedDecision } from "../../src/index.js";
import { AGENT, BASE, FakeApi, ORG, Signer, json } from "./fake.js";

const PARAMS = { amount: 50, customer: "c1" };
let signer: Signer;
let api: FakeApi;

beforeEach(async () => {
  signer = await new Signer().init();
  api = new FakeApi()
    .on("GET", "/.well-known/jwks.json", () => json(200, { keys: [signer.jwk()] }))
    .on("GET", "/api/v1/org", () => json(200, { id: ORG, name: "Org", slug: "org" }))
    .on("POST", "/api/v1/decisions/redeem", () => json(200, { valid: true, reason: "ok" }));
});

function verifier(options: Partial<ConstructorParameters<typeof DecisionVerifier>[0]> = {}) {
  return new DecisionVerifier({ baseUrl: BASE, apiKey: "agk_test", fetch: api.fetch, ...options });
}

async function reason(v: DecisionVerifier, token: string | null, extra: Record<string, unknown> = {}): Promise<string> {
  try {
    await v.verify(token, { tool: "refunds", action: "create", parameters: PARAMS, ...extra });
  } catch (error) {
    expect(error).toBeInstanceOf(DecisionRejected);
    return (error as DecisionRejected).reason;
  }
  throw new Error("verified");
}

describe("DecisionVerifier", () => {
  it("verifies online and redeems", async () => {
    const v = verifier();
    const result = await v.verify(await signer.token({ params: PARAMS, claims: { obl: { max_rows: 5 } } }), {
      tool: "refunds",
      action: "create",
      parameters: PARAMS,
    });
    expect(result.redeemed).toBe(true);
    expect(result.orgId).toBe(ORG);
    expect(result.agentId).toBe(AGENT);
    expect(result.resource).toBe("customer:c1");
    expect(result.obligations).toEqual({ max_rows: 5 });
    const redeem = api.last("POST", "/api/v1/decisions/redeem");
    expect(redeem.headers.authorization).toBe("Bearer agk_test");
    expect(JSON.parse(redeem.body).action_hash).toBe(result.actionHash);
    await v.verify(await signer.token({ params: PARAMS }), { tool: "refunds", action: "create", parameters: PARAMS });
    expect(api.count("GET", "/.well-known/jwks.json")).toBe(1);
    expect(api.count("GET", "/api/v1/org")).toBe(1);
  });

  it.each([
    [{ ttl: -30 }, "invalid_or_expired"],
    [{ audience: "agentguard" }, "invalid_or_expired"],
    [{ issuer: "http://evil.test" }, "invalid_or_expired"],
    [{ org: "00000000-0000-0000-0000-000000000000" }, "wrong_org"],
    [{ tool: "shell" }, "tool_mismatch"],
    [{ action: "delete" }, "action_mismatch"],
    [{ params: { amount: 5000, customer: "c1" } }, "params_mismatch"],
    [{ typ: "ag+jwt" }, "malformed"],
  ])("refuses %j", async (overrides, expected) => {
    const v = verifier({ leewaySeconds: 0 });
    const { params = PARAMS, ...rest } = overrides as { params?: Record<string, unknown> };
    expect(await reason(v, await signer.token({ params, ...rest }))).toBe(expected);
    expect(api.count("POST", "/api/v1/decisions/redeem")).toBe(0);
  });

  it("checks pins, missing and forged tokens", async () => {
    const v = verifier({ orgId: ORG });
    const token = await signer.token({ params: PARAMS });
    expect(await reason(v, token, { resource: "customer:c2" })).toBe("resource_mismatch");
    expect(await reason(v, token, { agentId: "other" })).toBe("wrong_agent");
    expect(await reason(v, token, { parameters: { a: NaN } })).toBe("params_mismatch");
    expect(await reason(v, null)).toBe("missing_token");
    expect(await reason(v, "garbage")).toBe("malformed");
    const forged = await (await new Signer(signer.kid).init()).token({ params: PARAMS });
    expect(await reason(v, forged)).toBe("invalid_or_expired");
    const noKid = token.replace(/^[^.]+/, Buffer.from(JSON.stringify({ alg: "EdDSA", typ: "agd+jwt" })).toString("base64url"));
    expect(await reason(v, noKid)).toBe("malformed");
    expect((await v.verify(token, { tool: "refunds", action: "create", parameters: PARAMS, resource: "customer:c1", agentId: AGENT })).redeemed).toBe(true);
    expect(api.count("GET", "/api/v1/org")).toBe(0);
  });

  it("refreshes keys for an unknown kid, rate limited", async () => {
    const v = verifier({ minRefreshMs: 60_000 });
    await v.verify(await signer.token({ params: PARAMS }), { tool: "refunds", action: "create", parameters: PARAMS });
    const rotated = await new Signer("kid-2").init();
    api.on("GET", "/.well-known/jwks.json", () =>
      json(200, { keys: [signer.jwk(), rotated.jwk(), { kty: "RSA", kid: "rsa" }, "junk"] }),
    );
    expect(await reason(v, await rotated.token({ params: PARAMS }))).toBe("unknown_key");
    expect(api.count("GET", "/.well-known/jwks.json")).toBe(1);
    v.minRefreshMs = 0;
    expect((await v.verify(await rotated.token({ params: PARAMS }), { tool: "refunds", action: "create", parameters: PARAMS })).redeemed).toBe(true);
    expect(api.count("GET", "/.well-known/jwks.json")).toBe(2);
  });

  it.each([
    [json(200, { valid: false, reason: "already_used" }), "already_used"],
    [json(200, { valid: false, reason: "action_mismatch" }), "params_mismatch"],
    [json(200, { valid: false }), "invalid_or_expired"],
    [json(503, {}), "guard_unavailable"],
    [json(401, { error: { code: "invalid_api_key" } }), "guard_unavailable"],
  ])("maps redeem outcomes (%#)", async (response, expected) => {
    api.on("POST", "/api/v1/decisions/redeem", () => response);
    expect(await reason(verifier(), await signer.token({ params: PARAMS }))).toBe(expected);
  });

  it("fails closed when AgentGuard is unreachable", async () => {
    api.on("POST", "/api/v1/decisions/redeem", () => {
      throw new TypeError("fetch failed");
    });
    expect(await reason(verifier(), await signer.token({ params: PARAMS }))).toBe("guard_unavailable");
    api.on("GET", "/.well-known/jwks.json", () => json(500, {}));
    expect(await reason(verifier({ orgId: ORG }), await signer.token({ params: PARAMS }))).toBe("guard_unavailable");
  });

  it("offline mode is not single use", async () => {
    const v = new DecisionVerifier({ baseUrl: BASE, orgId: ORG, offline: true, fetch: api.fetch });
    const token = await signer.token({ params: PARAMS });
    const opts = { tool: "refunds", action: "create", parameters: PARAMS };
    expect((await v.verify(token, opts)).redeemed).toBe(false);
    expect((await v.verify(token, opts)).redeemed).toBe(false);
    expect(api.count("POST", "/api/v1/decisions/redeem")).toBe(0);
  });

  it("validates options", () => {
    expect(() => new DecisionVerifier({ baseUrl: "x", apiKey: "k" })).toThrow(/http/);
    expect(() => new DecisionVerifier({ baseUrl: BASE })).toThrow(/API key/);
    expect(() => new DecisionVerifier({ baseUrl: BASE, offline: true })).toThrow(/orgId/);
    const v = new DecisionVerifier({ baseUrl: `${BASE}/`, apiKey: "k", issuer: "https://public.example/" });
    expect([v.baseUrl, v.issuer]).toEqual([BASE, "https://public.example"]);
  });
});

class FakeRes implements ResponseLike {
  locals: Record<string, unknown> = {};
  code = 200;
  body: unknown = null;
  headers: Record<string, string> = {};
  status(code: number) {
    this.code = code;
    return this;
  }
  set(name: string, value: string) {
    this.headers[name] = value;
    return this;
  }
  json(body: unknown) {
    this.body = body;
    return this;
  }
}

describe("requireDecision (Express)", () => {
  it("lets through only a verified token for this body", async () => {
    const mw = requireDecision(verifier(), { tool: "refunds", action: "create" });
    const run = async (body: unknown, token?: string, query: unknown = {}) => {
      const res = new FakeRes();
      let nexted = false;
      const headers: Record<string, string> = token ? { "x-agentguard-decision": token } : {};
      await mw({ body, query, headers }, res, () => {
        nexted = true;
      });
      return { res, nexted };
    };
    const missing = await run(PARAMS);
    expect(missing.res.code).toBe(401);
    expect(missing.res.headers["WWW-Authenticate"]).toBe("AgentGuard-Decision");
    const token = await signer.token({ params: PARAMS });
    const tampered = await run({ ...PARAMS, amount: 5000 }, token);
    expect(tampered.res.code).toBe(403);
    expect(tampered.res.body).toEqual({ error: { code: "params_mismatch", message: expect.any(String) } });
    const ok = await run(PARAMS, token);
    expect(ok.nexted).toBe(true);
    expect((ok.res.locals.agentguardDecision as VerifiedDecision).redeemed).toBe(true);
    const fromQuery = await run({}, await signer.token({ params: { q: "x" } }), { q: "x" });
    expect(fromQuery.nexted).toBe(true);
    api.on("POST", "/api/v1/decisions/redeem", () => json(503, {}));
    expect((await run(PARAMS, await signer.token({ params: PARAMS }))).res.code).toBe(503);
  });

  it("supports custom parameters, resource, header and passes other errors on", async () => {
    const mw = requireDecision<{ headers: Record<string, string>; params: { amount: string } }>(verifier(), {
      tool: "refunds",
      action: "create",
      header: "X-Decision",
      parameters: (req) => ({ amount: Number(req.params.amount), customer: "c1" }),
      resource: (_req, p) => `customer:${String(p.customer)}`,
      agentId: AGENT,
    });
    const res = new FakeRes();
    let nexted: unknown = "no";
    await mw({ headers: { "x-decision": await signer.token({ params: PARAMS }) }, params: { amount: "50" } }, res, (e) => {
      nexted = e;
    });
    expect(nexted).toBeUndefined();
    const broken = requireDecision(
      { verify: () => Promise.reject(new Error("bug")) } as unknown as DecisionVerifier,
      { tool: "t" },
    );
    await broken({ headers: { "x-agentguard-decision": ["a", "b"] } }, new FakeRes(), (e) => {
      nexted = e;
    });
    expect((nexted as Error).message).toBe("bug");
  });
});
