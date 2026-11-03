# Security

AgentGuard is a security product, so this page is about two things: how AgentGuard
protects the agents and resources behind it, and how it protects itself. The STRIDE
analysis and the OWASP agentic mapping are in [threat-model.md](threat-model.md); how to
report a vulnerability is in [SECURITY.md](../../SECURITY.md).

## The security model in one page

1. **Every agent is a principal.** It authenticates with its own credential, exchanged for
   a short-lived Ed25519 token that is re-checked on every call. Names, prompts and ids in
   request bodies never identify anyone ([identity.md](identity.md)).
2. **Every action is decided before it happens.** Deterministic policy, explicit deny wins,
   default deny in enforce mode, every decision recorded with its reason and policy
   version ([policy-engine.md](policy-engine.md)).
3. **Decisions are enforced, not advised.** AgentGuard runs HTTP, MCP and sandbox tools
   itself; in-process tools verify a single-use decision token bound to the exact action;
   the MCP gateway hides and refuses tools; the egress proxy refuses destinations
   ([HLD.md](HLD.md#enforcement-points)).
4. **People approve exact actions.** Bound to the action hash, used once, re-authorized at
   execution ([approvals.md](approvals.md)).
5. **Credentials stay inside.** Envelope encrypted, injected into the one call that needs
   them, bound to destination hosts, never returned ([secrets.md](secrets.md)).
6. **Untrusted content lowers privileges.** A run that read an injection is tainted and its
   high-risk actions need a person ([threat-detection.md](threat-detection.md)).
7. **Untrusted code is contained.** Unprivileged nsjail per run, no network unless policy
   grants the egress proxy ([sandbox.md](sandbox.md)).
8. **Everything is evidence.** A hash-chained, database-guarded, checkpointed audit log
   ([audit.md](audit.md)).
9. **Fail closed.** When AgentGuard cannot decide, the answer is deny.

## What AgentGuard guarantees

Within its enforcement points, and assuming the deployment is configured as described
below:

| Guarantee | Mechanism | Proven by |
| --- | --- | --- |
| A denied action never reaches a tool AgentGuard runs | Trusted execution: the tool's credentials are only inside AgentGuard | `test_a_denied_action_never_reaches_the_tool` |
| A protected function tool runs only for the exact allowed action, once, within the token's lifetime | Decision tokens: signature, action hash, expiry, online single-use redemption | `test_decision_tokens_are_bound_single_use_and_verifiable` |
| An action needing approval does not run before approval, with exactly the approved parameters, once | Action hash binding, conditional consume, re-authorization | `test_approval_is_bound_to_the_exact_parameters`, `test_an_approved_action_runs_once_through_agentguard` |
| Explicit deny beats every allow; no match is deny | Deny-overrides, default deny | property tests, `test_explicit_deny_overrides_any_allow` |
| Identity cannot be claimed in a body; revocation is immediate | Token-only identity, per-request re-check | `test_identity_comes_from_the_token_never_the_body` |
| A suspended or quarantined agent gets deny for every action | Pipeline pre-check, egress proxy check, empty MCP listing | `test_suspended_and_quarantined_agents_are_denied_and_revoked_ones_lose_tokens` |
| A secret value never appears in an API response, log line, audit record or error | Write-only API, redaction, hidden SQL parameters, leak check on outputs | `test_secret_values_never_leave_agentguard`, `test_secret_values_never_reach_the_logs` |
| Metadata addresses are never reached through any AgentGuard path, private ranges only by explicit CIDR rules, even after DNS rebinding | Network evaluation and peer checks | `test_the_egress_proxy_enforces_network_policy`, `test_ssrf_through_tool_configuration_is_refused` |
| Submitted code never runs in the API or worker | The sandbox service is the only executor | `test_code_runs_only_in_the_sandbox` |
| An edited, removed or reordered audit record is detected | Hash chain, triggers, signed checkpoints, `verify` | `test_tampering_is_detected_even_with_database_rules_switched_off` |
| No API, gateway call, approval, secret or audit read crosses organisations | `OrgScoped`, 404 on mismatch | `test_organisations_never_see_each_other`, `test_cross_tenant_approval_ids_are_unknown` |
| AgentGuard fails closed when its database or counters are unreachable | 503 `guard_unavailable` with `decision: deny` | `test_agentguard_fails_closed_when_its_database_is_unreachable` |

## What AgentGuard does not guarantee

Be precise about the edges:

- **Advice is not enforcement.** An agent that calls `authorize`, ignores the answer and
  calls a tool directly is not stopped. Use `execute`, the MCP gateway or decision-token
  verification for anything that matters; keep tool credentials out of agents.
- **Function tools must verify.** AgentGuard cannot force code it does not run to check
  tokens. A function tool without verification is only audited.
- **Direct network routes bypass the proxy.** The egress proxy only sees traffic sent to it.
  Make it the only route out (security groups, Compose networks), as the Terraform does.
- **Detectors miss things.** The injection guard and the classifier are signals. Content
  that never passes through AgentGuard (not scanned, not read through an AgentGuard-run
  tool) cannot taint a run. Low and medium risk actions of a tainted run proceed unless a
  policy says otherwise.
- **The model's own outputs are not guarded.** AgentGuard governs actions, not what the
  model says to its user, and not model spend (TokenShield does that).
- **Within an allowed action, the tool decides.** A permitted `UPDATE` with a broad `WHERE`
  is still permitted; write constraints and policies on parameters.
- **TLS contents are opaque to the proxy.** Policies decide by host and port; HTTP methods
  are known only for plain HTTP.
- **A database superuser** can drop the audit triggers and rewrite rows; signed checkpoints
  in a separate, locked bucket are what catch it. Somebody with both database access and
  KMS decrypt permission (or `LOCAL_MASTER_KEY`) can open secrets.
- **Signing key rotation and old checkpoints.** The key ring keeps retired keys for a day;
  checkpoints signed by a key retired longer ago fail signature verification. Keep the
  JWKS of each key you retire if you need to verify old checkpoints later.
- **Counters without Redis are per process.** With several replicas and no `REDIS_URL`,
  limits are enforced per replica.
- **Kernel exploits** escape any container sandbox; nsjail shares the host kernel.
- **On-behalf-of is context.** `on_behalf_of` is what the calling application states; it is
  used for limits and for the no-self-approval rule, not as authentication.

## Protecting AgentGuard itself

### Tenant isolation

Every tenant-owned table carries `org_id`; every query filters by the caller's
organisation; lookups by id compare `row.org_id` and answer 404 so ids of other
organisations are not confirmed. Agent tokens, decision tokens and proxy tokens carry
their organisation and are checked against it; a foreign decision token is recorded as a
`cross_tenant` threat. Policies scoped to another organisation's slug never apply.

### Input and transport

- Request bodies above `MAX_BODY_BYTES` (1 MB) are refused with 413 before parsing, by the
  declared length and while streaming (`test_bodies_are_bounded_before_parsing`).
- Tool responses above `MAX_TOOL_RESPONSE_BYTES` (5 MB) are cut off while streaming.
- Every Pydantic model at the boundary forbids unknown fields.
- Policy sources (200 KB), expressions (2000 characters, 32 levels), regular expressions
  (200 characters, subjects cut at 10 000) and parameter nesting (64 levels) are bounded.
- Security headers on every response (`X-Content-Type-Options`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy`, `Permissions-Policy`);
  `no-store` on authentication responses; CORS limited to `CORS_ORIGINS`.
- `FORWARDED_ALLOW_IPS` limits who may set `X-Forwarded-For` (the load balancer's network).

### Outbound requests

Every URL AgentGuard calls (HTTP tools, MCP servers, webhooks, SIEM, OPA, TokenShield, the
classifier) is checked when saved and again when used: http or https, canonical host, no
metadata hosts or addresses, public addresses unless allowed, redirects off for tools, the
connected peer checked ([network-guard.md](network-guard.md)).

### Rate limits and lockout

`/oauth/token` per address (`TOKEN_RPM`), sign-in (`LOGIN_RPM`) and sign-up (`SIGNUP_RPM`)
per address, lockout per account and address, per-agent limits for everything else.

### Production boot guards

With `ENVIRONMENT=production`, `Settings.guard()` refuses to start when:

1. `SESSION_SECRET`, `TOKEN_PEPPER` or `SANDBOX_TOKEN` is a known placeholder, contains
   `not-for-production`, or is shorter than 32 characters;
2. `KEY_MODE=local` and `LOCAL_MASTER_KEY` is insecure in the same way;
3. `SESSION_SECRET`, `TOKEN_PEPPER` and `SANDBOX_TOKEN` are not all different;
4. `AGENTGUARD_CLOUD=aws` and `AWS_ENDPOINT_URL` is set (an emulator endpoint);
5. `COOKIE_SECURE` is false;
6. `MAIL_BACKEND=log` (approval emails would go nowhere);
7. `CORS_ORIGINS` contains `*`;
8. `ALLOW_PRIVATE_URLS` is true (SSRF);
9. `AI_ALLOW_PRIVATE_ENDPOINTS` is true while `SIGNUP_ENABLED` is true (any stranger could
   become a tenant admin and aim the classifier at internal hosts);
10. `VAULT_URL` is set and not https;
11. `PUBLIC_URL` or `PUBLIC_API_URL` is not https.

All problems are reported together. `test_production_refuses_unsafe_configuration` covers
each one.

## Compliance report

`GET /api/v1/compliance/report` maps the organisation's live state to the OWASP Top 10 for
Agentic Applications (2026), ASI01 to ASI10. Each risk has checks computed from the
organisation's own data (policies, tools, agents, decisions, threats, limits, the audit
chain): a risk is `met` when every check passes, `partial` when some do, `gap` when none
do, and each failing check says what to do. The report is signed (Ed25519) together with
the audit chain head, and exports as JSON or Markdown
(`GET /api/v1/compliance/export`) so a copy handed to an auditor can be verified later
(`test_compliance_report_maps_owasp_risks_with_live_evidence`). It is evidence that
controls exist and work, not a certification. The mapping is in
[threat-model.md](threat-model.md#owasp-top-10-for-agentic-applications-2026).

## Operator checklist

For a production deployment:

- Set `ENVIRONMENT=production` so the boot guards run; generate secrets with
  `openssl rand -hex 32` (Terraform does this into Secrets Manager).
- Use `KEY_MODE=kms`. Keep the KMS key policy narrow: only the API and worker task roles
  decrypt.
- Keep the organisation in **enforce** mode once rolled out; audit mode allows everything.
- Make the egress proxy the only route out for agents and the sandbox; give agents no
  direct internet access.
- Give tools to agents through `execute`, the MCP gateway, or decision-token verification;
  do not hand tool credentials to agents.
- Write a default network policy with `default_action: deny`.
- Keep the built-in policies enabled; tune their conditions instead of disabling them.
- Turn on `require_signed_requests` for agents on untrusted networks.
- Bind credentials to source networks (`allowed_cidrs`) where agents have stable
  addresses, and rotate them regularly.
- Set threat responses for `critical` and `high` that match your tolerance; the default
  quarantines and revokes on critical.
- Configure Redis for more than one API replica; size it so it never fills (it runs with
  `noeviction`, and a full cache makes AgentGuard deny).
- Turn off `SIGNUP_ENABLED` after creating your organisation; use OIDC with allowed domains.
- Keep `STDIO_ALLOWED_COMMANDS` empty unless you need a stdio MCP server, and list exact
  commands.
- Leave `AI_ALLOW_PRIVATE_ENDPOINTS` off unless the classifier is in your network.
- Ship logs to CloudWatch (or your SIEM) for an independent copy, and connect the SIEM
  integration for audit records.
- Run `agentguard verify` on a schedule and alert on a non-zero exit.
- Keep `FORWARDED_ALLOW_IPS` to the load balancer's network.
