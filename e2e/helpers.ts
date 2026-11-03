import { type APIRequestContext, type Browser, type BrowserContext, expect, type Page, request } from "@playwright/test";

export const BASE = process.env.WEB_URL || "http://localhost:5110";
export const MAILPIT = process.env.MAILPIT_URL || "http://localhost:5125";
export const PASSWORD = process.env.AG_DEMO_PASSWORD || "Demo-Pass-2026";

/** The demo people (make demo), one per dashboard role. */
export const USERS = {
  admin: "nora@kestrel.example",
  officer: "omar@kestrel.example",
  reviewer: "priya@kestrel.example",
  reviewer2: "daniel@kestrel.example",
  auditor: "elena@kestrel.example",
} as const;
export type Who = keyof typeof USERS;

/** Session files written by global-setup.ts, one per demo person. */
export const authFile = (who: Who) => `.auth/${who}.json`;

/** Mutations through the API carry the CSRF header the web app sends. */
export const CSRF = { "x-agentguard-csrf": "1" };

/** A per-run suffix so suites can run repeatedly against the same demo database. */
export const RUN = process.env.E2E_RUN || Date.now().toString(36).slice(-6);
let counter = 0;
/** A name unique to this run and call: e2e-<run>-<n>. */
export const unique = (prefix = "e2e") => `${prefix}-${RUN}-${++counter}`;

/** Fail the test on any console error the page reports. */
export function watchConsole(page: Page): string[] {
  const errors: string[] = [];
  page.on("console", (m) => {
    if (m.type() === "error") errors.push(m.text());
  });
  page.on("pageerror", (e) => errors.push(e.message));
  return errors;
}

async function retrying(fn: () => Promise<import("@playwright/test").APIResponse>) {
  for (let i = 0; i < 10; i++) {
    const resp = await fn();
    if (resp.status() !== 429) return resp;
    await new Promise((r) => setTimeout(r, Number(resp.headers()["retry-after"] ?? "5") * 1000));
  }
  return fn();
}

/** A browser context signed in as a demo person (their saved session). */
export async function contextAs(browser: Browser, who: Who): Promise<BrowserContext> {
  return browser.newContext({ storageState: authFile(who), baseURL: BASE, viewport: { width: 1440, height: 900 } });
}

/** An API client signed in as a demo person (their saved session). */
export async function apiAs(who: Who): Promise<APIRequestContext> {
  return request.newContext({ baseURL: BASE, extraHTTPHeaders: CSRF, storageState: authFile(who) });
}

/** JSON from the API, asserting success. */
export async function call<T = unknown>(ctx: APIRequestContext, method: string, path: string, data?: unknown): Promise<T> {
  const resp = await retrying(() => ctx.fetch(path, { method, data }));
  expect(resp.status(), `${method} ${path}: ${await resp.text()}`).toBeLessThan(300);
  return (resp.status() === 204 ? null : await resp.json()) as T;
}

/** Poll until ``fn`` returns something truthy. */
export async function eventually<T>(fn: () => Promise<T | null | undefined | false>, timeoutMs = 60_000): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  let last: unknown = null;
  while (Date.now() < deadline) {
    last = await fn();
    if (last) return last as T;
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`condition never held (last: ${JSON.stringify(last)?.slice(0, 200)})`);
}

export interface Credential {
  client_id: string;
  client_secret: string;
}

export interface TestAgent {
  id: string;
  slug: string;
  credential: Credential;
}

/**
 * Register an agent for one test, through the management API. Defaults copy the demo's
 * support agent (support project and role, the network policy that lets the payments
 * tool reach the mock provider), so its decisions follow the demo policies.
 */
export async function registerAgent(admin: APIRequestContext, opts: { roles?: string[]; project?: string; network?: string } = {}): Promise<TestAgent> {
  const projects = await call<{ id: string; slug: string }[]>(admin, "GET", "/api/v1/projects");
  const networks = await call<{ id: string; name: string }[]>(admin, "GET", "/api/v1/network-policies");
  const slug = unique("e2e-agent");
  const out = await call<{ agent: { id: string; slug: string }; credential: Credential }>(admin, "POST", "/api/v1/agents/register", {
    slug,
    name: `E2E ${slug}`,
    description: "Created by an end-to-end test.",
    framework: "python",
    project_id: projects.find((p) => p.slug === (opts.project ?? "support"))?.id ?? null,
    roles: opts.roles ?? ["support"],
    network_policy_id: networks.find((n) => n.name === (opts.network ?? "finance-providers"))?.id ?? null,
  });
  return { id: out.agent.id, slug: out.agent.slug, credential: out.credential };
}

/**
 * What the SDK does: exchange the credential at /oauth/token for a short-lived token, then
 * call the decision API with it.
 */
export async function agentClient(cred: Credential): Promise<APIRequestContext> {
  const anon = await request.newContext({ baseURL: BASE });
  const resp = await retrying(() => anon.post("/oauth/token", { form: { grant_type: "client_credentials", client_id: cred.client_id, client_secret: cred.client_secret } }));
  expect(resp.status(), await resp.text()).toBe(200);
  const { access_token } = (await resp.json()) as { access_token: string };
  await anon.dispose();
  return request.newContext({ baseURL: BASE, extraHTTPHeaders: { authorization: `Bearer ${access_token}` } });
}

export interface AgentDecision {
  decision_id: string;
  decision: string;
  allowed: boolean;
  reason_code: string;
  reason: string;
  policy?: string | null;
  approval?: { id: string; status: string } | null;
}

export async function authorize(agent: APIRequestContext, body: Record<string, unknown>): Promise<AgentDecision> {
  return call<AgentDecision>(agent, "POST", "/api/v1/authorize", body);
}

/** A refund the demo's refund-approvals policy holds for a person (above 200 EUR). */
export function refund(amount: number, extra: Record<string, unknown> = {}) {
  return {
    tool: "payments.refund",
    action: "refund",
    parameters: { customer_id: `${RUN}${++counter}`, amount, currency: "EUR", reason: "End-to-end test refund" },
    ...extra,
  };
}

/** Messages Mailpit received for an address after a moment. */
export async function mailsTo(address: string, after: number): Promise<{ ID: string; Subject: string; Created: string }[]> {
  const ctx = await request.newContext({ baseURL: MAILPIT });
  try {
    const found = await (await ctx.get(`/api/v1/search?query=${encodeURIComponent(`to:${address}`)}`)).json();
    return (found.messages ?? []).filter((m: { Created: string }) => Date.parse(m.Created) >= after);
  } finally {
    await ctx.dispose();
  }
}
