# @euron/agentguard (Node.js)

The Node.js SDK for [Euron Open AgentGuard](../../README.md), the self-hosted security
gateway for AI agents. It is part of the open-source initiative of **ENGAGESPHERE TECHNOLOGY
PRIVATE LIMITED** and is MIT licensed. TypeScript, ESM, Node.js 20 or newer, one runtime
dependency (`jose`, for verifying decision tokens).

The package is not on npm yet (publishing is on the roadmap). Until then build it from this
repository and depend on it by path:

```bash
cd sdks/node && pnpm install && pnpm build
# in your project: "dependencies": { "@euron/agentguard": "link:../path/to/sdks/node" }
```

```ts
import { AgentGuard } from "@euron/agentguard";

const guard = new AgentGuard({ baseUrl: "http://localhost:5130", clientId, clientSecret });

const decision = await guard.authorize("refunds", { action: "create", parameters: { amount: 50, customer: "c-1" } });
if (decision.allowed) await refund(50, "c-1");
else if (decision.needsApproval) await decision.waitForApproval(300_000);
```

| What | Where |
| --- | --- |
| `AgentGuard` | `authorize`, `execute`, `scan`, `askPerson`, `waitForApproval`, `endRun`, `me`, `mcpSettings`, `guard(fn, options)` |
| `DecisionVerifier` | verify and redeem a decision token on the tool side |
| `requireDecision` from `@euron/agentguard/express` | Express (connect-style) middleware that does the verification |
| `actionHash`, `canonicalJson` | the action hash, byte for byte the same as the API |

Every failure to decide is a denial: `authorize` resolves to `decision: "deny"` with
`reasonCode: "guard_unavailable"` when AgentGuard cannot be reached. The full guide is
[docs/guides/sdk-node.md](../../docs/guides/sdk-node.md).

## Development

```bash
pnpm install
pnpm test                                    # unit tests with a fake fetch
AGENTGUARD_URL=http://localhost:5130 pnpm test:integration   # a real API
pnpm lint && pnpm typecheck && pnpm build
```
