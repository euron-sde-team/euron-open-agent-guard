// The Node.js quickstart: decide actions, guard a function, and verify a decision token in
// an Express route that protects its own tool.
//
//   export AGENTGUARD_URL=http://localhost:5130 AGENTGUARD_CLIENT_ID=ag_... AGENTGUARD_CLIENT_SECRET=ags_...
//   export AGENTGUARD_API_KEY=agk_...   # read scope, for the verifier
//   pnpm start

import express from "express";

import { ActionDenied, AgentGuard, ApprovalRequired, DecisionVerifier } from "@euron/agentguard";
import { requireDecision } from "@euron/agentguard/express";

const baseUrl = process.env.AGENTGUARD_URL ?? "http://localhost:5130";
const guard = new AgentGuard({
  baseUrl,
  clientId: process.env.AGENTGUARD_CLIENT_ID,
  clientSecret: process.env.AGENTGUARD_CLIENT_SECRET,
  runId: "node-quickstart",
});

const me = await guard.me();
console.log(`Signed in as agent ${me.agent}\n`);

// 1. Decide actions.
for (const [tool, action, parameters] of [
  ["refunds", "create", { amount: 40, customer: "c-4001" }],
  ["refunds", "create", { amount: 900, customer: "c-4001" }],
  ["shell", "call", { command: "cat /etc/passwd" }],
]) {
  const d = await guard.authorize(tool, { action, parameters });
  console.log(`${tool} ${JSON.stringify(parameters)} -> ${d.decision}: ${d.reason}`);
}

// 2. Guard a function: it only runs when AgentGuard allows the call.
const refund = guard.guard(({ amount, customer }) => `refunded ${amount} to ${customer}`, {
  tool: "refunds",
  action: "create",
});
for (const amount of [25, 900, 20000]) {
  try {
    console.log(`refund(${amount}) -> ${await refund({ amount, customer: "c-4002" })}`);
  } catch (error) {
    if (error instanceof ApprovalRequired) console.log(`refund(${amount}) -> waits for approval ${error.approval?.id}`);
    else if (error instanceof ActionDenied) console.log(`refund(${amount}) -> denied (${error.reasonCode})`);
    else throw error;
  }
}

// 3. A tool that protects itself: an Express route that needs a decision token.
const verifier = new DecisionVerifier({ baseUrl, apiKey: process.env.AGENTGUARD_API_KEY });
const app = express();
app.post("/refunds", express.json(), requireDecision(verifier, { tool: "refunds", action: "create" }), (req, res) => {
  res.json({ refunded: req.body.amount, agent: res.locals.agentguardDecision.agent });
});
const server = app.listen(0, "127.0.0.1");
await new Promise((resolve) => server.once("listening", resolve));
const service = `http://127.0.0.1:${server.address().port}/refunds`;

const body = { amount: 45, customer: "c-4003" };
const { decisionToken } = await guard.authorize("refunds", { action: "create", parameters: body, wantToken: true });
const post = (payload) =>
  fetch(service, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-AgentGuard-Decision": decisionToken },
    body: JSON.stringify(payload),
  });
console.log();
const statuses = [];
for (const [name, payload] of [["other amount", { ...body, amount: 4500 }], ["valid token", body], ["replayed", body]]) {
  const response = await post(payload);
  statuses.push(response.status);
  console.log(`${name.padEnd(13)} -> ${response.status} ${await response.text()}`);
}
server.close();
await guard.endRun();
process.exit(statuses.join(",") === "403,200,403" ? 0 : 1);
