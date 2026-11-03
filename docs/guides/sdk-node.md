# Node.js SDK

`@euron/agentguard` connects a Node.js agent to AgentGuard (`AgentGuard`) and lets a tool
verify that AgentGuard allowed the exact call it is about to perform (`DecisionVerifier`,
`requireDecision` for Express). TypeScript with strict types, ESM only, Node.js 20 or newer,
and one runtime dependency: `jose`, for Ed25519 JWT verification. It mirrors the
[Python SDK](sdk-python.md); read that guide for the concepts (decisions, failing closed,
approvals, why client-side checks are not enough), this one for the Node.js API.

## Install

The package is not on npm yet (publishing is on the roadmap). Build it from the repository:

```bash
cd sdks/node && pnpm install && pnpm build
```

and depend on it by path (`"@euron/agentguard": "link:../sdks/node"`), as
[examples/node-quickstart](../../examples/node-quickstart/) does.

## Connect an agent

```ts
import { AgentGuard } from "@euron/agentguard";

const guard = new AgentGuard({
  baseUrl: "http://localhost:5130",
  clientId: process.env.AGENTGUARD_CLIENT_ID!,
  clientSecret: process.env.AGENTGUARD_CLIENT_SECRET!,
  signingSecret: undefined,       // set when the agent must sign its requests
  runId: "ticket-4711",           // optional default run
  timeoutMs: 10_000,
  failMode: "closed",             // the default
  fetch: undefined,               // a custom fetch (tests, proxies)
});
```

Tokens are exchanged at `/oauth/token`, cached, refreshed before expiry and on a 401
`invalid_token` or `token_revoked` (once). Concurrent calls share one exchange.

## Decisions

```ts
const d = await guard.authorize("refunds", {
  action: "create",
  parameters: { amount: 700, customer: "c-1" },
  resource: undefined, runId: undefined, onBehalfOf: "maria@example.com",
  context: { channel: "chat" }, wantToken: false,
});
d.allowed; d.decision; d.wouldBe; d.mode; d.reasonCode; d.reason; d.obligations;
d.approval;  // { id, status, url, expiresAt, required, comment } | null
d.decisionToken; d.actionHash; d.needsApproval; d.restricted; d.failedClosed;
d.raiseForDecision();   // returns d, or throws ApprovalRequired / ActionDenied
```

Fields are the API's in camelCase (`reason_code` is `reasonCode`); the untouched response is
in `d.raw`. `execute(tool, options)` has AgentGuard run the tool (`d.executed`, `d.result`).
`askPerson(tool, { ...options, reason })` asks a person first.

**Fail closed.** `authorize`, `execute` and `askPerson` never reject for a failure to decide:
they resolve to a denial with `decisionId: null`, `failedClosed: true` and `reasonCode`
`guard_unavailable` (network error, timeout, 5xx, the API's 503) or the API's error code.
`failMode: "open"` allows on unreachability only while the last decision seen said
`mode: "audit"`; it never allows in enforce mode or for an error the API answered with.

## Approvals

```ts
if (d.needsApproval) {
  const status = await d.waitForApproval(300_000);     // long-polls 30 s at a time
  if (status.approved) await guard.authorize("refunds", { action: "create", parameters });  // allowed once
}
await guard.approvalStatus(id, { wait: 10 });
await guard.waitForApproval(id, { timeoutMs: 60_000 });
```

## Guarding a function

```ts
import { currentDecision } from "@euron/agentguard";

const refund = guard.guard(
  async ({ amount, customer }: { amount: number; customer: string }) => {
    const decision = currentDecision();          // obligations, decision id
    return payments.refund(amount, customer);
  },
  { tool: "refunds", action: "create", resource: (p) => `customer:${p.customer}`, wait: true },
);
await refund({ amount: 40, customer: "c-1" });   // rejects with ActionDenied or ApprovalRequired
```

The parameters are the first argument when the function takes one plain object, otherwise
`{ args: [...] }`; pass `parameters: (...args) => ({...})` to choose. `currentDecision()`
works across `await` (it uses `AsyncLocalStorage`).

## Other calls

`scan(content, { source, spotlight, runId })` (rejects with `GuardUnavailable` when the scan
cannot run), `endRun(runId?)`, `me()`, `mcpSettings(runId?)` (the `/mcp` URL and headers for
any MCP client; the token in them expires, so fetch new settings when it does) and
`accessToken({ force })`.

## Verifying decision tokens

```ts
import { DecisionVerifier, DecisionRejected } from "@euron/agentguard";

const verifier = new DecisionVerifier({ baseUrl: "http://localhost:5130", apiKey: "agk_..." });
try {
  const ok = await verifier.verify(token, { tool: "refunds", action: "create", parameters: body });
} catch (error) {
  if (error instanceof DecisionRejected) refuse(error.reason);
}
```

The checks are the Python SDK's, in the same order: header, signature against the cached
JWKS (refetched for an unknown key id at most every `minRefreshMs`, default 10 s), audience,
issuer and expiry (`leewaySeconds`, default 5), organisation (default: the API key's), tool,
action, pinned resource and agent, the locally recomputed action hash, and the online
redemption that makes the token single use. `offline: true` (with `orgId`) skips the
redemption: the token is then **not single use**. Pass `issuer` when the API's public URL
differs from `baseUrl`.

## Express

```ts
import express from "express";
import { requireDecision } from "@euron/agentguard/express";

app.post("/refunds", express.json(), requireDecision(verifier, { tool: "refunds", action: "create" }),
  (req, res) => res.json({ ok: true, decision: res.locals.agentguardDecision.decisionId }));
```

The middleware reads `X-AgentGuard-Decision` and the parameters from `req.body` (parse JSON
first), or `req.query` when there is no body, and answers 401 (missing token), 403 (any failed
check) or 503 (AgentGuard unreachable) with `{ error: { code, message } }`. Options:
`parameters(req)`, `resource` (a string or `(req, params) => string`), `agentId`, `header`.
Express is not a dependency; any connect-style framework with `req.headers`, `res.status()`
and `res.json()` works.

## The action hash and numbers

`actionHash(orgId, agentId, tool, action, resource, params)` matches the API byte for byte for
every value this SDK can send; the shared vectors in `sdks/testdata/action-hash-vectors.json`
(17 shared cases and 2000 floats) pass. JavaScript has one number type, so an integer above
2**53 cannot be represented exactly and an integral float such as `9007199254740994.0` that a
Python agent sent hashes differently here (the vectors mark those 3 cases `python_only`).
Integers of 1e21 or more are sent by `JSON.stringify` in exponent form and hashed as floats,
like the API does. NaN, Infinity, BigInt and lone surrogates are refused. Keep amounts as
integers in minor units below `Number.MAX_SAFE_INTEGER`, or as strings.
