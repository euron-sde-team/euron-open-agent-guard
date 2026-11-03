import { expect, request, test } from "@playwright/test";

import { agentClient, apiAs, authorize, BASE, call, contextAs, CSRF, refund, registerAgent, RUN } from "../helpers";

/**
 * AC20: no API, gateway call, approval, secret or audit read crosses organisations (404);
 * dashboard roles (org admin, security officer, reviewer, auditor) can do exactly what their
 * role allows.
 */
test("another organisation sees none of Kestrel's agents, approvals, secrets or audit records", async ({ browser }) => {
  const admin = await apiAs("admin");
  const agent = await registerAgent(admin);
  const held = await authorize(await agentClient(agent.credential), refund(260));
  const secrets = await call<{ id: string }[]>(admin, "GET", "/api/v1/secrets");
  const policies = await call<{ id: string }[]>(admin, "GET", "/api/v1/policies");

  // A second organisation, signed up through the API.
  const other = await request.newContext({ baseURL: BASE, extraHTTPHeaders: CSRF });
  const signup = await other.post("/api/v1/auth/signup", {
    data: { org_name: `Other Org ${RUN}`, name: "Olga Other", email: `olga-${RUN}-${Date.now() % 100000}@other.example`, password: "Other-Org-2026" },
  });
  expect(signup.status(), await signup.text()).toBe(201);

  for (const path of [`/api/v1/agents/${agent.id}`, `/api/v1/approvals/${held.approval!.id}`, `/api/v1/secrets/${secrets[0]!.id}`, `/api/v1/policies/${policies[0]!.id}`]) {
    const resp = await other.get(path);
    expect(resp.status(), path).toBe(404);
  }
  // Writes are refused the same way.
  expect((await other.post(`/api/v1/agents/${agent.id}/suspend`, { data: { reason: "x" } })).status()).toBe(404);
  expect((await other.post(`/api/v1/approvals/${held.approval!.id}/approve`, { data: { comment: "x" } })).status()).toBe(404);
  // Its lists hold only its own records.
  expect(await call<unknown[]>(other, "GET", "/api/v1/agents")).toEqual([]);
  const audit = await call<{ items: { target_id: string | null }[] }>(other, "GET", "/api/v1/audit-logs?limit=200");
  expect(audit.items.some((e) => e.target_id === agent.id)).toBe(false);

  // And the dashboard shows the other organisation a not-found page, not Kestrel's agent.
  const state = await other.storageState();
  const ctx = await browser.newContext({ storageState: state, baseURL: BASE });
  const page = await ctx.newPage();
  await page.goto(`/agents/${agent.id}`);
  await expect(page.getByText("Could not load this agent")).toBeVisible();
  await expect(page.getByText(agent.slug)).toHaveCount(0);
  await Promise.all([ctx.close(), other.dispose(), admin.dispose()]);
});

test("each role sees exactly the controls it may use, and the API agrees", async ({ browser }) => {
  const admin = await apiAs("admin");
  const agent = await registerAgent(admin);
  const held = await authorize(await agentClient(agent.credential), refund(270));
  const approval = `/approvals/${held.approval!.id}`;

  // Auditor: reads everything, changes nothing.
  const auditorCtx = await contextAs(browser, "auditor");
  const auditor = await auditorCtx.newPage();
  await auditor.goto("/agents");
  await expect(auditor.getByRole("button", { name: "Register agent" })).toBeDisabled();
  await auditor.goto(approval);
  await expect(auditor.getByRole("button", { name: "Approve" })).toBeDisabled();
  await auditor.goto("/integrations");
  await auditor.getByRole("tab", { name: "Connections" }).click();
  await expect(auditor.getByText("Org admins manage connections")).toBeVisible();
  const auditorApi = await apiAs("auditor");
  expect((await auditorApi.post("/api/v1/agents/register", { data: { slug: `nope-${RUN}`, name: "Nope" } })).status()).toBe(403);
  expect((await auditorApi.post(`/api/v1/approvals/${held.approval!.id}/approve`, { data: { comment: "x" } })).status()).toBe(403);

  // Reviewer: votes on approvals, cannot register agents.
  const reviewerCtx = await contextAs(browser, "reviewer");
  const reviewer = await reviewerCtx.newPage();
  await reviewer.goto(approval);
  await expect(reviewer.getByRole("button", { name: "Approve" })).toBeEnabled();
  await reviewer.goto("/agents");
  await expect(reviewer.getByRole("button", { name: "Register agent" })).toBeDisabled();

  // Security officer: changes security configuration, not people or integrations.
  const officerCtx = await contextAs(browser, "officer");
  const officer = await officerCtx.newPage();
  await officer.goto("/agents");
  await expect(officer.getByRole("button", { name: "Register agent" })).toBeEnabled();
  await officer.goto("/integrations");
  await officer.getByRole("tab", { name: "Connections" }).click();
  await expect(officer.getByText("Org admins manage connections")).toBeVisible();
  const officerApi = await apiAs("officer");
  expect((await officerApi.get("/api/v1/api-keys")).status()).toBe(403);

  // Org admin: everything, including connections and people.
  const adminCtx = await contextAs(browser, "admin");
  const page = await adminCtx.newPage();
  await page.goto("/integrations");
  await page.getByRole("tab", { name: "Connections" }).click();
  await expect(page.getByRole("heading", { name: /TokenShield/ })).toBeVisible();
  await page.goto("/settings");
  await expect(page.getByRole("button", { name: "Invite" })).toBeEnabled();

  await Promise.all([auditorCtx.close(), reviewerCtx.close(), officerCtx.close(), adminCtx.close(), auditorApi.dispose(), officerApi.dispose(), admin.dispose()]);
});
