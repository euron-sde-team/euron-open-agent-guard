# ADR-0002: A native deterministic policy engine, with an optional OPA adapter that can only add caution

- **Status:** Accepted
- **Date:** 2026-11-02

## Context

Every action an agent takes is decided by policy before it runs, so the engine is on the
hot path of every tool call. The people who write policies are platform and security
engineers, not necessarily Rego authors; the brief's example policy is YAML
(`production-database-protection` with `read: allow`, `write: require_approval`,
`delete: deny`). A decision must be explainable (which rule, which version, why), and the
same input with the same policy versions must always give the same answer, so a recorded
decision can be re-run in simulation.

Open Policy Agent is the standard general-purpose engine and many organisations already
have Rego. Making it mandatory would add a network hop to every decision, a second
language for the simple cases, and a component whose outage would stop every agent.

## Decision

AgentGuard ships its own engine (`policies/dsl.py`, `policies/expr.py`,
`policies/engine.py`):

- Policies are YAML, validated strictly (unknown keys, unknown decisions, invalid
  expressions and approvals nobody could give are refused at save time) and compiled into
  a typed form stored with each immutable version.
- Conditions use a small expression language parsed by hand into a tree (never `eval`),
  with bounded size, nesting and regular expressions.
- Evaluation tests every rule of every active policy; the strongest matching decision
  wins in a fixed order, `quarantine > deny > require_approval > restrict > allow`. Ties
  are explained by the most specific rule, then by policy name and rule index, so the
  explanation is deterministic too. With no matching rule, permissions decide; with no
  permission, the default is deny in enforce mode.
- A condition that cannot be evaluated makes its rule match only if the rule denies or
  quarantines: an error can add caution, never grant.

An organisation can also connect OPA (`integrations/opa.py`). AgentGuard sends OPA the same
evaluation input and combines the answer deny-overrides with its own: OPA's decision is
taken only when it is stronger. When OPA cannot be reached, sensitive tools are denied
(`opa_unavailable`) and other tools keep the native decision.

## Consequences

**Good**
- No extra network hop by default; policies are cached per process under a generation
  counter, so evaluation is in-memory.
- Deny-overrides makes policies composable: adding a policy can only make things
  stricter unless it is an allow for something nothing else covers.
- Determinism is property-tested (`test_property_strongest_decision_wins_and_order_does_not_matter`,
  `test_property_evaluation_is_a_pure_function`), which is what makes simulation honest.
- Organisations with Rego keep it, and it cannot weaken the native result
  (`test_opa_can_add_caution_but_never_grant`).

**Bad / caveats**
- A second policy language to learn for teams that already standardised on Rego (they can
  still use OPA for the extra checks).
- The expression language is deliberately small: no loops, no user functions, no
  arithmetic. Anything richer belongs in OPA.
- Simulation re-runs the native engine only; it does not call OPA.

## Alternatives considered

- **OPA as the only engine**: mature and general, but every decision would depend on a
  sidecar, and simple policies would need Rego.
- **Cedar**: a well-designed authorization language with formal analysis; a Rust
  dependency and its own schema model, and still not the YAML format the brief asks for.
- **First-match evaluation** (like a firewall): easy to explain, but the outcome depends on
  rule order, and one misplaced allow above a deny silently opens a hole.
