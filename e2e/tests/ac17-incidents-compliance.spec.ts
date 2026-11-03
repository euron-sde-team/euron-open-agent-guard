import { readFile } from "node:fs/promises";

import { expect, test } from "@playwright/test";

import { apiAs, call, registerAgent, unique, watchConsole } from "../helpers";

/**
 * AC17: an incident gets a timeline from linked events, evidence, containment actions and
 * resolution; it exports as Markdown and JSON; the compliance report maps controls to OWASP
 * ASI01 to ASI10 with live evidence and exports.
 */
test("an incident from opening to resolution, with evidence, containment and exports", async ({ page }) => {
  const errors = watchConsole(page);
  const admin = await apiAs("admin");
  const agent = await registerAgent(admin);
  const threats = await call<{ id: string; summary: string }[]>(admin, "GET", "/api/v1/threats?limit=5");
  expect(threats.length, "the demo has threats").toBeGreaterThan(0);
  const threat = threats[0]!;
  const title = `Suspicious exports by ${agent.slug} ${unique("inc")}`;

  await page.goto("/incidents");
  await page.getByRole("button", { name: "Open incident" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Title").fill(title);
  await dialog.getByRole("combobox", { name: "Agent involved" }).click();
  await page.getByRole("option", { name: agent.slug }).click();
  await dialog.getByLabel("Summary").fill("Exported more rows than its task needs.");
  await dialog.getByRole("button", { name: "Open incident" }).click();
  await expect(page).toHaveURL(/\/incidents\/[0-9a-f-]{36}$/);
  await expect(page.getByRole("heading", { name: title })).toBeVisible();

  // Timeline note.
  await page.getByLabel("Add a note").fill("Paged the support lead.");
  await page.getByRole("button", { name: "Add note" }).click();
  await expect(page.getByText("Paged the support lead.")).toBeVisible();

  // Evidence: a frozen snapshot of a threat, with its hash.
  await page.getByRole("button", { name: "Add evidence" }).click();
  const ev = page.getByRole("dialog");
  await ev.getByRole("combobox", { name: "Kind" }).click();
  await page.getByRole("option", { name: "Threat" }).click();
  await ev.getByLabel("Id").fill(threat.id);
  await ev.getByRole("button", { name: "Attach" }).click();
  await expect(page.getByText("Evidence attached and hashed.")).toBeVisible();
  await expect(page.getByText(/^sha256/).first()).toBeVisible();

  // Containment: quarantine the agent involved.
  await page.getByRole("button", { name: "Quarantine agent" }).click();
  const contain = page.getByRole("dialog");
  await contain.getByLabel("Reason").fill("Contain while we investigate the exports.");
  await contain.getByRole("button", { name: "Quarantine agent" }).click();
  await expect(page.getByText("Quarantine agent: done. It is on the timeline.")).toBeVisible();
  const after = await call<{ status: string }>(admin, "GET", `/api/v1/agents/${agent.id}`);
  expect(after.status).toBe("quarantined");

  // Resolution.
  await page.getByRole("button", { name: "Resolve", exact: true }).click();
  const resolve = page.getByRole("dialog");
  await resolve.getByLabel("Root cause").fill("A prompt asked for the full customer list.");
  await resolve.getByLabel("Resolution").fill("Export capped at 100 rows by policy; agent stays quarantined until reviewed.");
  await resolve.getByRole("button", { name: "Resolve incident" }).click();
  await expect(page.getByText(/resolved\.$/)).toBeVisible();
  await expect(page.getByText("A prompt asked for the full customer list.").first()).toBeVisible();

  // Exports.
  const [md] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", { name: "Markdown" }).click()]);
  const markdown = await readFile((await md.path())!, "utf8");
  expect(markdown).toContain(title);
  expect(markdown).toContain("A prompt asked for the full customer list.");
  const [js] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", { name: "JSON" }).click()]);
  const json = JSON.parse(await readFile((await js.path())!, "utf8")) as { evidence: { sha256: string }[] };
  expect(json.evidence.length).toBeGreaterThan(0);
  expect(json.evidence[0]!.sha256).toMatch(/^[0-9a-f]{64}$/);

  expect(errors).toEqual([]);
  await admin.dispose();
});

test("the compliance report maps ASI01 to ASI10 with evidence, signed, and exports", async ({ page }) => {
  await page.goto("/compliance");
  for (let i = 1; i <= 10; i++) await expect(page.getByText(`ASI${String(i).padStart(2, "0")}`, { exact: true })).toBeVisible();
  await expect(page.getByText("Agent goal hijack")).toBeVisible();
  await expect(page.getByText("Ed25519 signature")).toBeVisible();
  await expect(page.getByText("Audit chain head", { exact: true })).toBeVisible();
  const [md] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", { name: "Markdown" }).click()]);
  const text = await readFile((await md.path())!, "utf8");
  expect(text).toContain("OWASP Top 10 for Agentic Applications");
  expect(text).toContain("## ASI10");
  expect(text).toMatch(/signed with key/);
  const [js] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", { name: "JSON" }).click()]);
  const report = JSON.parse(await readFile((await js.path())!, "utf8")) as { controls: { id: string }[]; signature: { ed25519: string } };
  expect(report.controls.map((c) => c.id)).toEqual(["ASI01", "ASI02", "ASI03", "ASI04", "ASI05", "ASI06", "ASI07", "ASI08", "ASI09", "ASI10"]);
  expect(report.signature.ed25519.length).toBeGreaterThan(40);
});
