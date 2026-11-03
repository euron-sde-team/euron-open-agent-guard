# Architecture decision records

Decisions a newcomer would question, with the context and the alternatives. A decision
that is reversed or extended gets a new ADR; old ones are not edited.

| ADR | Decision |
| --- | --- |
| [0001](0001-mit-licence.md) | MIT licence |
| [0002](0002-native-policy-engine-optional-opa.md) | A native, deterministic policy engine; OPA is an optional adapter that can only add caution |
| [0003](0003-trusted-execution-and-decision-tokens.md) | Enforcement through trusted execution and single-use decision tokens; client-side checks are audit only |
| [0004](0004-approvals-bound-to-the-action-hash.md) | Approvals are bound to a canonical action hash and re-authorized at execution |
| [0005](0005-run-taint-over-classifiers.md) | A run that read an injection is tainted; permissions, not a classifier, are the defence |
| [0006](0006-ed25519-short-lived-agent-tokens.md) | Agents exchange credentials for short-lived Ed25519 tokens, re-checked on every call |
| [0007](0007-hash-chained-audit-single-sealer.md) | A hash-chained audit log, sealed by one writer per organisation, guarded by database rules and signed checkpoints |
| [0008](0008-unprivileged-nsjail-sandbox.md) | Untrusted code runs in an unprivileged nsjail sandbox service, never in the API |
| [0009](0009-egress-proxy-and-peer-checks.md) | An egress forward proxy plus connected-peer checks on every outbound path |
| [0010](0010-postgres-outbox-and-redis-counters.md) | Jobs as a Postgres transactional outbox; Redis for counters, rate limits and pub/sub |
| [0011](0011-mcp-gateway-absorbed-from-mcp-hub.md) | The MCP gateway and catalog are part of AgentGuard (absorbed from MCP Hub) |
| [0012](0012-domains-in-one-package-sdks-separate.md) | Domains are packages inside one API package; SDKs live under `sdks/` |
