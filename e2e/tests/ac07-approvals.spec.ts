import { expect, test } from "@playwright/test";

import { agentClient, apiAs, authorize, call, contextAs, eventually, mailsTo, refund, registerAgent, USERS, watchConsole } from "../helpers";

/**
 * AC7: an action that requires approval does not run until approved; a two-person rule
 * needs two distinct reviewers with the required role and refuses the requester approving
 * their own request; changing any parameter after approval requires a new approval; an
 * expired approval cannot be used; a rejection carries its reason to the agent; email
 * notifications go out; the approval history cannot be modified.
 *
 * Each test registers its own agent and creates its own held refund (the demo policy
 * refund-approvals holds refunds above 200 EUR, and needs two people above 1000 EUR).
 */
test.describe("AC7 approvals", () => {
  test("two distinct reviewers, no self-approval, exact parameters, runs only once approved", async ({ browser }) => {
    const admin = await apiAs("admin");
    const agent = await registerAgent(admin);
    const client = await agentClient(agent.credential);
    // Acting for Priya: she may not approve her own agent's request.
    const body = refund(1500, { on_behalf_of: USERS.reviewer });
    const held = await authorize(client, body);
    expect(held.decision).toBe("require_approval");
    expect(held.allowed).toBe(false);
    const id = held.approval!.id;

    // Nothing ran: the agent sees it pending, nothing executed.
    const status = await call<{ status: string; result: unknown }>(client, "GET", `/api/v1/approvals/${id}/status`);
    expect(status.status).toBe("pending");
    expect(status.result ?? null).toBeNull();

    // Priya (the requester's person) is refused, and the page says why.
    const priyaCtx = await contextAs(browser, "reviewer");
    const priya = await priyaCtx.newPage();
    const priyaErrors = watchConsole(priya);
    await priya.goto(`/approvals/${id}`);
    await expect(priya.getByText("Refunds above 1000 EUR need two people").first()).toBeVisible();
    await expect(priya.getByText('"amount": 1500')).toBeVisible();
    await expect(priya.getByRole("button", { name: "Approve" })).toBeDisabled();
    await expect(priya.getByText("You cannot approve an action taken on your own behalf")).toBeVisible();

    // Daniel approves: one of two.
    const danielCtx = await contextAs(browser, "reviewer2");
    const daniel = await danielCtx.newPage();
    await daniel.goto(`/approvals/${id}`);
    await expect(daniel.getByText("0 of 2")).toBeVisible();
    await daniel.getByLabel("Comment").fill("Checked the order history.");
    await daniel.getByRole("button", { name: "Approve" }).click();
    await expect(daniel.getByText("Your approval is recorded. The next stage needs another person.")).toBeVisible();
    await expect(daniel.getByText("1 of 2")).toBeVisible();
    // The same person cannot count twice.
    await daniel.reload();
    await expect(daniel.getByRole("button", { name: "Approve" })).toBeDisabled();
    await expect(daniel.getByText("You already voted on this stage")).toBeVisible();
    expect((await call<{ status: string }>(client, "GET", `/api/v1/approvals/${id}/status`)).status).toBe("pending");

    // Nora approves: the second distinct person. AgentGuard then runs it, once.
    const noraCtx = await contextAs(browser, "admin");
    const nora = await noraCtx.newPage();
    await nora.goto(`/approvals/${id}`);
    await nora.getByRole("button", { name: "Approve" }).click();
    await expect(nora.getByText("Approved. The exact parameters you saw may now run, once.")).toBeVisible();
    await expect(nora.getByText("Executed").first()).toBeVisible({ timeout: 60_000 });
    await expect(nora.getByRole("heading", { name: "History" })).toBeVisible();

    // A different amount with the same approval is a new request: refused.
    const swapped = await authorize(client, { ...body, parameters: { ...body.parameters, amount: 1499 }, approval_id: id });
    expect(swapped.allowed).toBe(false);
    expect(swapped.reason_code).toBe("approval_mismatch");

    // The history is append-only: no edit or delete control anywhere on the page.
    await expect(nora.getByRole("button", { name: /edit|delete/i })).toHaveCount(0);
    expect(priyaErrors).toEqual([]);
    await Promise.all([priyaCtx.close(), danielCtx.close(), noraCtx.close(), client.dispose(), admin.dispose()]);
  });

  test("a rejection needs a reason, and the agent receives it", async ({ browser }) => {
    const admin = await apiAs("admin");
    const agent = await registerAgent(admin);
    const client = await agentClient(agent.credential);
    const body = refund(350);
    const held = await authorize(client, body);
    const id = held.approval!.id;

    const ctx = await contextAs(browser, "reviewer");
    const page = await ctx.newPage();
    await page.goto(`/approvals/${id}`);
    await page.getByRole("button", { name: "Reject" }).click();
    await expect(page.getByText("Say why you reject it: the agent receives this reason.")).toBeVisible();
    await page.getByLabel("Comment").fill("Refund the original card, not store credit.");
    await page.getByRole("button", { name: "Reject" }).click();
    await expect(page.getByText("Rejected. The agent receives your reason.")).toBeVisible();
    await expect(page.getByText("Rejected").first()).toBeVisible();

    const seen = await call<{ status: string; comment: string }>(client, "GET", `/api/v1/approvals/${id}/status`);
    expect(seen).toMatchObject({ status: "rejected", comment: "Refund the original card, not store credit." });
    // A rejected approval never unlocks the action.
    const retry = await authorize(client, { ...body, approval_id: id });
    expect(retry.allowed).toBe(false);
    await Promise.all([ctx.close(), client.dispose(), admin.dispose()]);
  });

  test("an expired approval cannot be used", async ({ browser }) => {
    const admin = await apiAs("admin");
    const agent = await registerAgent(admin);
    const client = await agentClient(agent.credential);
    const body = refund(420);
    const held = await authorize(client, body);
    const id = held.approval!.id;

    const ctx = await contextAs(browser, "officer");
    const page = await ctx.newPage();
    await page.goto(`/approvals/${id}`);
    await page.getByRole("button", { name: "Expire now" }).click();
    const dialog = page.getByRole("dialog");
    await dialog.getByLabel(/Reason/).fill("The customer withdrew the claim.");
    await dialog.getByRole("button", { name: "Expire" }).click();
    await expect(page.getByText("Request expired.")).toBeVisible();
    await expect(page.getByText("Expired").first()).toBeVisible();

    // Not even a reviewer can approve it now, and the agent cannot use it.
    const reviewer = await apiAs("reviewer2");
    const vote = await reviewer.post(`/api/v1/approvals/${id}/approve`, { data: { comment: "too late" } });
    expect(vote.status()).toBeGreaterThanOrEqual(400);
    const use = await authorize(client, { ...body, approval_id: id });
    expect(use.allowed).toBe(false);
    await Promise.all([ctx.close(), client.dispose(), admin.dispose(), reviewer.dispose()]);
  });

  test("reviewers are emailed when an approval is requested", async () => {
    const admin = await apiAs("admin");
    const agent = await registerAgent(admin);
    const client = await agentClient(agent.credential);
    const since = Date.now() - 2_000;
    const held = await authorize(client, refund(380));
    expect(held.decision).toBe("require_approval");
    // The refund-approvals stage names reviewers and security officers.
    const mails = await eventually(async () => {
      const found = await mailsTo(USERS.reviewer, since);
      return found.length ? found : null;
    }, 60_000);
    expect(mails.length).toBeGreaterThan(0);
    await Promise.all([client.dispose(), admin.dispose()]);
  });
});
