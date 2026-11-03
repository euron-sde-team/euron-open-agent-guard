# ADR-0004: Approvals bound to the action hash and re-authorized at execution

- **Status:** Accepted
- **Date:** 2026-11-02

## Context

A person approves what they saw: refund 450 EUR to customer 2048. If the approval were
bound to the tool or to the request id, an agent (or an attacker steering it) could change
the amount after approval, or reuse one approval for a second refund. And the world moves
between approval and execution: a policy can be tightened, the agent can be quarantined,
the kill switch can be switched on.

## Decision

- Every action has a canonical **action hash** (`core/canonical.py`): SHA-256 over a domain
  separator and the canonical JSON of the organisation, agent, tool, action, resource and
  parameters. Canonical means keys sorted, no insignificant whitespace, strings in Unicode
  NFC, integral floats written as integers, NaN and infinity refused. The SDKs implement
  the same function and are tested against shared vectors (`sdks/testdata/`).
- An approval request stores that hash and the exact parameters, sealed. The reviewer sees
  the parameters; any change produces a different hash and therefore a new request
  (`approval_mismatch` when an agent names an approval for different parameters).
- An approved request is used **once**: `consume()` moves it from `approved` to `executed`
  with one conditional `UPDATE`.
- Execution goes back through the whole decision pipeline at that moment. For tools
  AgentGuard runs, the worker job `approvals.execute` rebuilds the request from the sealed
  parameters and calls `execute`; for function tools, the agent repeats its request and
  receives an allow with a decision token. A policy that now denies, a suspended agent or
  the kill switch wins over the approval, and the request is marked `failed` with the
  reason.

## Consequences

**Good**
- An approval cannot be stretched to other parameters
  (`test_approval_is_bound_to_the_exact_parameters`) or used twice
  (`test_an_approved_action_runs_once_through_agentguard`).
- A policy change after approval wins (`test_policy_changed_after_approval_wins_at_execution`).
- Parameters at rest in the approvals table are ciphertext.

**Bad / caveats**
- Agents that build parameters non-deterministically (a timestamp in the body) can never
  match their own approval; they must keep the parameters stable between the request and
  the retry.
- An approval that is consumed by an `allow` from a now-relaxed policy is not needed, and
  the request may stay `approved` until it expires (see [approvals.md](../approvals.md)).

## Alternatives considered

- **Approve by request id**: simple, but the parameters can be swapped after approval.
- **Approve a tool for a time window** ("finance-agent may refund for the next hour"):
  useful, and expressible as a lease or a policy; not what a reviewer of one action means.
- **Execute directly on approval without re-checking**: faster, but the approval would
  outrank a later deny.
