import { expect, request, test } from "@playwright/test";

import { authorize, BASE, RUN, watchConsole } from "../helpers";

/**
 * AC1: a fresh organisation can register an agent, get a credential and receive its first
 * decision in under five minutes of steps. Signs up a new organisation through the form,
 * follows the onboarding to register an agent, copies the credential the dialog shows once,
 * makes the SDK's two calls (token exchange, authorize) and sees the decision in the agent's
 * activity.
 */
test.use({ storageState: { cookies: [], origins: [] } });

test("a new organisation gets its first decision in minutes", async ({ page }) => {
  const started = Date.now();
  const errors = watchConsole(page);
  const email = `founder-${RUN}-${Math.random().toString(36).slice(2, 6)}@ac1.example`;

  await page.goto("/signup");
  await page.getByLabel("Organisation").fill(`AC1 Robotics ${RUN}`);
  await page.getByLabel("Your name").fill("Ada Founder");
  await page.getByLabel("Work email").fill(email);
  await page.getByLabel("Password", { exact: true }).fill("First-Agent-2026");
  await page.getByRole("button", { name: "Create organisation" }).click();
  await expect(page).toHaveURL(/\/overview$/);

  // Onboarding says what to do first.
  await expect(page.getByText("Get AgentGuard between your agents and their tools")).toBeVisible();
  await page.getByRole("link", { name: "Register an agent" }).click();
  await expect(page).toHaveURL(/\/agents\?register=1/);

  const register = page.getByRole("dialog");
  await register.getByLabel("Name", { exact: true }).fill("Order assistant");
  await register.getByRole("button", { name: "Register and issue credential" }).click();

  // The credential, shown once.
  const shown = page.getByRole("dialog");
  await expect(shown.getByText("Copy the credential now")).toBeVisible();
  const codes = shown.locator("code");
  const clientId = (await codes.nth(0).innerText()).trim();
  const clientSecret = (await codes.nth(1).innerText()).trim();
  expect(clientId).toMatch(/^ag_/);
  expect(clientSecret.length).toBeGreaterThan(20);
  await expect(shown.getByText("from euron_agentguard import AgentGuard")).toBeVisible();
  await shown.getByRole("button", { name: "I stored the secrets" }).click();

  // What the SDK does with it.
  const anon = await request.newContext({ baseURL: BASE });
  const tokenResp = await anon.post("/oauth/token", { form: { grant_type: "client_credentials", client_id: clientId, client_secret: clientSecret } });
  expect(tokenResp.status(), await tokenResp.text()).toBe(200);
  const { access_token } = (await tokenResp.json()) as { access_token: string };
  const agent = await request.newContext({ baseURL: BASE, extraHTTPHeaders: { authorization: `Bearer ${access_token}` } });
  const decision = await authorize(agent, { tool: "orders.lookup", action: "read", parameters: { order: "A-1" } });
  // A fresh organisation enforces default deny: nothing is registered or allowed yet.
  expect(decision.decision_id).toBeTruthy();
  expect(decision.decision).toBe("deny");

  // The decision is on the agent's page.
  await page.getByRole("link", { name: /Order assistant/ }).click();
  await expect(page.getByRole("heading", { name: "Recent decisions" })).toBeVisible();
  await expect(page.getByText("orders.lookup.read")).toBeVisible();
  await expect(page.getByRole("button", { name: /Open decision orders\.lookup\.read/ }).getByText("Deny")).toBeVisible();

  expect(Date.now() - started).toBeLessThan(5 * 60_000);
  expect(errors).toEqual([]);
  await Promise.all([anon.dispose(), agent.dispose()]);
});
