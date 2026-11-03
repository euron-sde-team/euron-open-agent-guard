import { expect, test } from "@playwright/test";

import { agentClient, apiAs, authorize, call, PASSWORD, refund, registerAgent, unique, USERS, watchConsole } from "../helpers";

/**
 * AC22: sign in, see the demo agents, open a held payment, approve it and watch it execute;
 * open a quarantined agent's incident; write a policy in the builder, simulate it against
 * history, activate it, and see the next decision follow it.
 */
test.describe("AC22 five-minute path", () => {
  test("sign in, see the demo agents, approve a held payment and watch it execute", async ({ browser }) => {
    // A held payment waiting for a reviewer (an agent of this test, like the demo's).
    const admin = await apiAs("admin");
    const agent = await registerAgent(admin);
    const body = refund(640);
    const held = await authorize(await agentClient(agent.credential), body);
    expect(held.decision).toBe("require_approval");

    // Sign in through the form, as a reviewer.
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    const errors = watchConsole(page);
    await page.goto("/login");
    await page.getByLabel("Work email").fill(USERS.reviewer);
    await page.getByLabel("Password", { exact: true }).fill(PASSWORD);
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await expect(page).toHaveURL(/\/overview$/);
    await expect(page.getByText("Decisions, last 24 hours")).toBeVisible();

    // The demo agents.
    await page.getByRole("link", { name: "Agents" }).first().click();
    for (const slug of ["support-agent", "finance-agent", "research-agent", "ops-agent", "coding-agent"]) {
      await expect(page.getByText(slug, { exact: false }).first()).toBeVisible();
    }
    await expect(page.getByText("Quarantined").first()).toBeVisible();

    // The held payment, from the queue.
    await page.getByRole("link", { name: /^Approvals/ }).first().click();
    const customer = String((body.parameters as { customer_id: string }).customer_id);
    await page.getByRole("link", { name: new RegExp(`customer:${customer}`) }).click();
    await expect(page.getByText(`"customer_id": "${customer}"`)).toBeVisible();
    await expect(page.getByText('"amount": 640')).toBeVisible();
    await page.getByRole("button", { name: "Approve" }).click();
    await expect(page.getByText("Approved. The exact parameters you saw may now run, once.")).toBeVisible();
    // AgentGuard runs it through the trusted path: watch it happen on the page.
    await expect(page.getByText("Executed").first()).toBeVisible({ timeout: 60_000 });
    await expect(page.getByText('"status": "succeeded"')).toBeVisible();
    expect(errors).toEqual([]);
    await Promise.all([ctx.close(), admin.dispose()]);
  });

  test("open the quarantined agent's incident", async ({ page }) => {
    const admin = await apiAs("admin");
    const agents = await call<{ id: string; slug: string; status: string }[]>(admin, "GET", "/api/v1/agents?status=quarantined");
    const ops = agents.find((a) => a.slug === "ops-agent");
    expect(ops, "the demo quarantines ops-agent").toBeTruthy();

    await page.goto("/agents");
    await page.getByRole("combobox", { name: "Filter by status" }).click();
    await page.getByRole("option", { name: "Quarantined" }).click();
    await page.getByRole("link", { name: /ops-agent/ }).click();
    await expect(page.getByText("Every action of this agent is denied.")).toBeVisible();
    await page.getByRole("link", { name: "Review threats" }).click();
    await expect(page).toHaveURL(/\/threats\?agent=/);
    await page.getByRole("link", { name: /ops-agent tried to read/ }).first().click();
    await page.getByRole("link", { name: "Open the incident" }).click();
    await expect(page).toHaveURL(/\/incidents\/[0-9a-f-]{36}$/);
    await expect(page.getByRole("heading", { name: /ops-agent/ })).toBeVisible();
    await expect(page.getByRole("link", { name: "ops-agent" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Timeline" })).toBeVisible();
    await admin.dispose();
  });

  test("write a policy, simulate it against history, activate it, and the next decision follows it", async ({ page }) => {
    const errors = watchConsole(page);
    const admin = await apiAs("admin");
    // An agent allowed to read customers by its role, with one recorded decision.
    const agent = await registerAgent(admin, { roles: ["reader"] });
    const client = await agentClient(agent.credential);
    const read = { tool: "crm.get_customer", action: "read", parameters: { customer_id: "1024" } };
    const before = await authorize(client, read);
    expect(before.decision).toBe("allow");

    const name = unique("e2e-no-reads");
    await page.goto("/policies/new");
    await page.getByRole("tab", { name: "YAML" }).click();
    await page.getByLabel("Policy YAML").fill(
      [
        `name: ${name}`,
        "description: End-to-end test policy, blocks one agent from reading customers.",
        "scope:",
        `  agents: [${agent.slug}]`,
        "tools: [crm.get_customer]",
        "rules:",
        "  - actions: [read]",
        "    decision: deny",
        "    reason: Customer reads are paused for this agent",
        "",
      ].join("\n"),
    );
    await expect(page.getByText("Compiles")).toBeVisible();

    // Simulate against the last 7 days of real decisions.
    await page.getByRole("button", { name: "Simulate" }).click();
    await expect(page.getByText(/^[1-9][\d,]* of [\d,]+ recorded decisions would change\.$/)).toBeVisible({ timeout: 30_000 });
    await page.getByText(/The changed decisions/).click();
    await expect(page.getByText(new RegExp(`${agent.slug} → crm\\.get_customer\\.read`)).first()).toBeVisible();

    // Create and activate.
    await page.getByRole("button", { name: "Create policy" }).click();
    const dialog = page.getByRole("dialog");
    await dialog.getByLabel("What changed").fill("Pause customer reads for the end-to-end agent");
    await dialog.getByRole("button", { name: "Save and activate" }).click();
    await expect(page.getByText(`${name} v1 is active. The next decision follows it.`)).toBeVisible();
    await expect(page).toHaveURL(/\/policies\/[0-9a-f-]{36}$/);

    // The next decision follows it.
    const after = await authorize(client, read);
    expect(after.decision).toBe("deny");
    expect(after.policy).toBe(name);

    // And the agent's activity shows it.
    await page.goto(`/agents/${agent.id}`);
    await expect(page.getByText(`${name} v1`).first()).toBeVisible();
    expect(errors).toEqual([]);
    await Promise.all([client.dispose(), admin.dispose()]);
  });
});
