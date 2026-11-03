# ADR-0003: Enforcement through trusted execution and decision tokens

- **Status:** Accepted
- **Date:** 2026-11-02

## Context

An authorization service that only answers "allowed or not" is advice. If the agent's own
code calls the tool after `if decision.allowed:`, then a compromised or confused agent can
skip the check, call the tool with different parameters than the ones that were decided,
or replay an old allow. A guard must stand in the path.

There are two kinds of tools. Some AgentGuard can call itself: an HTTP endpoint, a tool of
an MCP server, a piece of code for the sandbox. Others only exist inside the agent's
process or inside the organisation's own service (a Python function, a FastAPI route).

## Decision

Two enforcement points, chosen by the tool's kind:

1. **Trusted execution** (`POST /api/v1/execute`, `decisions/execute.py`) for `http`, `mcp`
   and `sandbox` tools. AgentGuard decides and then runs the action itself: it builds the
   request from the tool's registered configuration, injects secrets the agent never
   sees, applies obligations, checks the network policy and the connected peer, and
   scans the result before returning it. The only path to the tool is through the
   decision, because the agent does not hold the tool's credentials.
2. **Decision tokens** for `function` tools. An allowed decision carries a single-use
   Ed25519 JWT (`typ: agd+jwt`, audience `agentguard-decision`) naming the decision, the
   agent, the tool, the action, the resource, the action hash and the obligations, valid
   for `DECISION_TOKEN_TTL_S` (60 seconds by default). The tool verifies it before acting:
   signature against the JWKS, expiry, its own hash of the parameters it received, and
   then redeems it online (`POST /api/v1/decisions/redeem`), which marks it used with one
   conditional `UPDATE`. A second redemption fails.

`authorize` without either is still offered, for audit mode and for gradual adoption; the
documentation says plainly that a client-side check is not enforcement.

## Consequences

**Good**
- A denied action never reaches an AgentGuard-run tool
  (`test_a_denied_action_never_reaches_the_tool`).
- A protected function tool refuses a call without a token, with a token for other
  parameters, an expired token, or a token already used
  (`test_decision_tokens_are_bound_single_use_and_verifiable`).
- The SDKs make the tool side three lines (`require_decision` for FastAPI, the Express
  middleware for Node.js).

**Bad / caveats**
- Trusted execution puts AgentGuard on the data path of HTTP, MCP and sandbox tools: its
  latency and availability become the tool's.
- Redemption needs a network call from the tool to AgentGuard; offline verification alone
  (signature, hash, expiry) cannot stop a replay within the token's lifetime.
- `function` tools are only protected if their owners add verification. AgentGuard cannot
  force code it does not run.

## Alternatives considered

- **Advice only** (most authorization APIs): simplest, and exactly the gap this product
  exists to close.
- **A sidecar proxy in front of every tool**: strong, but it needs deployment work per
  tool and does not cover in-process functions.
- **Long-lived signed allow tokens**: no redemption call, but replayable until expiry.
