# Threat model

STRIDE over the components that matter, then the OWASP Top 10 for Agentic Applications
(2026) mapped to AgentGuard's controls. Controls are described in [security.md](security.md)
and the subsystem pages; this page maps threats to them and states what remains.

## Assets

| Asset | Where |
| --- | --- |
| The resources agents act on (databases, payments, email, files, code) | Behind tools; reached through AgentGuard's enforcement points |
| Tool credentials and other managed secrets | Postgres (envelope encrypted), Secrets Manager, Vault, the host environment |
| Agent credentials and tokens | `agent_credentials` (hashes and sealed signing secrets); tokens in agents' memory |
| Signing keys (agent, decision and proxy tokens, audit checkpoints) | `signing_keys`, private halves sealed |
| Policies, permissions, network policies, limits | Postgres |
| Decisions, approvals, the audit chain, checkpoints | Postgres, the audit bucket |
| Deployment secrets (`SESSION_SECRET`, `TOKEN_PEPPER`, `LOCAL_MASTER_KEY`, `SANDBOX_TOKEN`) | Environment, Secrets Manager |

## Trust boundaries

1. Agents (untrusted: they may be steered by injected content) to the API, the MCP
   gateway and the egress proxy.
2. Content agents read (untrusted by definition): web pages, tickets, tool outputs, MCP
   tool descriptions.
3. People in the dashboard (trusted to their role) to the web app and API.
4. The API and worker to tools, MCP servers, webhooks, the classifier, OPA, TokenShield.
5. The API and worker to the sandbox (submitted code is untrusted).
6. The application to Postgres, Redis, KMS, S3 (trusted infrastructure, with the database
   rules and checkpoints as a check on it).

## STRIDE

| Component | Threat | Category | Control | Residual risk |
| --- | --- | --- | --- | --- |
| Identity | An agent claims to be another agent (name in the body, forged token) | Spoofing | Identity only from the Ed25519 token; signature, audience, issuer, expiry, credential and token version checked per request (`test_identity_comes_from_the_token_never_the_body`) | A stolen token works until it expires (15 min default) or the credential is revoked |
| Identity | A stolen client secret is used from elsewhere | Spoofing | `allowed_cidrs`, rotation, revocation, rate-limited exchange, uniform `invalid_client` errors | Without CIDR binding, a leaked secret works from anywhere until revoked |
| Identity | A captured authorize request is replayed | Spoofing, tampering | Signed requests with timestamp window and Postgres nonces (`test_signed_requests_refuse_replays_and_stale_or_missing_signatures`) | Only for agents that sign; `/mcp` and the egress proxy use the token alone |
| Decision API | Parameters changed after the decision | Tampering | Approvals and decision tokens bound to the action hash; trusted execution uses the decided parameters | Function tools that do not verify tokens |
| Decision API | Policy bypass by skipping `authorize` | Elevation | Trusted execution and decision-token verification; agents never hold tool credentials | Tools whose credentials an agent still holds |
| Decision API | AgentGuard degraded into allowing (database or Redis down) | Elevation | Fail closed: 503 `guard_unavailable` with `decision: deny`; SDKs treat errors as deny (`test_agentguard_fails_closed_when_its_database_is_unreachable`) | Audit mode allows by design; the SDK's `fail_mode="open"` is honoured only in audit mode |
| Policy engine | A broken or adversarial condition grants | Elevation | Errors match only deny rules; parsed, never `eval`; bounded size, depth, regex | A regex near the limits can cost CPU per evaluation |
| Policy engine | A policy edit silently opens access | Elevation, repudiation | Versions, audit records, simulation before activation, deny-overrides | A person with the security officer role can write an allow; that is their job, and it is audited |
| Approvals | A reviewer approves one thing, another runs | Tampering | Action hash, sealed exact parameters shown to the reviewer, single use, re-authorization at execution | Reviewers can still be misled by benign-looking parameters (see ASI09) |
| Approvals | Self-approval or one person passing a two-person rule | Elevation | `forbid_requester` on `on_behalf_of`, distinct voters per stage, role checks (`test_two_person_rule_needs_two_distinct_eligible_reviewers`) | `on_behalf_of` is asserted by the calling application |
| Approvals | Approval history rewritten | Repudiation | Append-only trigger, audit records | A database superuser |
| Secrets | A value leaks through the API, logs, errors or audit | Information disclosure | Write-only API, redaction, `hide_parameters`, leak check on outputs (`test_secret_values_never_reach_the_logs`) | External stores' values are not in the output leak check |
| Secrets | A tool configuration redirects a secret to an attacker | Information disclosure | `allowed_hosts` per secret, network policy, redirects off | Secrets without `allowed_hosts` go wherever the tool config points |
| Secrets | Database theft opens secrets | Information disclosure | Envelope encryption, data keys wrapped by KMS or a key outside the database | Database plus KMS decrypt (or `LOCAL_MASTER_KEY`) |
| Prompt injection | Content steers an agent into a harmful action | Elevation | Run taint and `tainted-run-guard`; output scanning and spotlighting; data exfiltration guard (`test_injected_content_taints_the_run_and_holds_its_next_risky_action`) | Undetected injections; content that never passes AgentGuard; low and medium risk actions |
| MCP gateway | A tool description carries instructions, or changes after review | Tampering | Description scan, fingerprints, `pending_review` on change (`test_a_changed_tool_definition_is_held_until_reviewed`) | Changes between two discoveries (10 min) take effect for calls in that window |
| MCP gateway | Discovering tools the agent may not use | Information disclosure | `could_allow` filter; hidden tools refused like unknown ones | Optimistic listing shows conditionally allowed tools |
| MCP catalog | A stdio server runs an arbitrary command | Elevation | `STDIO_ALLOWED_COMMANDS` allowlist, security officer role | Allowlisted commands run with the API container's privileges |
| Network | SSRF to metadata or internal services | Information disclosure, elevation | Metadata always refused; private only by CIDR rules; canonical hosts; resolve once (proxy) and peer checks (tools, webhooks) (`test_ssrf_through_tool_configuration_is_refused`) | MCP sessions and the classifier check the URL, not the peer of each call |
| Network | Exfiltration through allowed destinations | Information disclosure | Data exfiltration guard, transfer limits, new-destination detection | A destination the policy allows can receive data |
| Sandbox | Code escapes, reads host files, starves the service | Elevation, denial of service | nsjail per run, rlimits, read-only root, no network, hostile suite ([sandbox.md](sandbox.md)) | Kernel vulnerabilities |
| Sandbox | Code steals the proxy credential | Spoofing | The relay adds it; the program never sees it (`test_the_program_cannot_read_the_credential`) | The token is valid for 15 minutes for that agent and run |
| Limits | An agent floods tools or AgentGuard | Denial of service | Atomic limits, loop guard, burst detection, suspension, kill switch (`test_limits_hold_exactly_under_concurrency`) | Without Redis, limits are per replica |
| Audit | Records edited, removed or reordered | Tampering, repudiation | Hash chain, triggers, signed checkpoints in a locked bucket, `verify` (`test_tampering_is_detected_even_with_database_rules_switched_off`) | Records not yet sealed (seconds); old checkpoints after key rotation (see security.md) |
| Dashboard | Session theft, CSRF | Spoofing, tampering | HttpOnly, Secure, SameSite cookie; CSRF header; revocation on sign-out; lockout | A stolen session works until it expires or is signed out |
| Dashboard | A user raises their own role | Elevation | Role changes are org admin only (`test_people_cannot_raise_their_own_role`) | An org admin is trusted |
| SSO | Account takeover through the identity provider | Spoofing | Issuer, audience, nonce, PKCE; allowed domains; binding to `sub` | A provider that omits `email_verified` is trusted for the address on first sign-in |
| Tenancy | One organisation reads another's data | Information disclosure | `OrgScoped`, 404 on mismatch, tokens carry their organisation (`test_organisations_never_see_each_other`) | A future endpoint that forgets the filter; the integration suite is the guard |
| Configuration | Production runs with demo secrets or unsafe options | Elevation | `Settings.guard()` (eleven checks) | Settings outside the guard |
| Webhooks | Forged deliveries to a receiver | Spoofing | HMAC over timestamp and body, delivery id | Receivers must verify |

## OWASP Top 10 for Agentic Applications 2026

The compliance report (`GET /api/v1/compliance/report`) computes these checks live for each
organisation.

| Risk | What it is | AgentGuard controls | Live checks in the report |
| --- | --- | --- | --- |
| **ASI01** Agent goal hijack | Instructions hidden in content redirect the agent | Injection guard with normalisation, run taint, `tainted-run-guard`, output scanning, spotlighting, optional classifier | Tool outputs are scanned; the tainted-run guard is active; injections detected or none occurred |
| **ASI02** Tool misuse | Agents call tools in ways nobody authorised | Tool registry with schemas and constraints, permissions, policies, default deny, enforce mode, trusted execution, decision tokens | Decisions enforced and unknown actions denied; tools validate their parameters; sensitive tools covered by approvals or denials |
| **ASI03** Identity and privilege abuse | Agents act with someone else's identity or more privilege than needed | Per-agent credentials and tokens, revocation, project boundary, least-privilege roles, signed requests | Every agent has its own identity; credentials are rotated (older than 90 days flagged); the project boundary is enforced |
| **ASI04** Agentic supply chain | A tool or MCP server changes under the agent | MCP fingerprints, change review, description scanning, stdio allowlist | MCP tool changes are held for review; no change waiting for review; stdio servers are allowlisted |
| **ASI05** Unexpected code execution | Agent-written code runs where it can do harm | Sandbox service only, nsjail, no network by default, sandbox memory limits | Code runs in the sandbox; sandbox memory is limited |
| **ASI06** Memory and context poisoning | Poisoned content persists in what the agent remembers | Content scan and spotlighting before content enters memory, `wrap_untrusted`, taint | Content can be scanned and spotlighted; detection taints runs on injection |
| **ASI07** Insecure inter-agent communication | One agent impersonates or instructs another | Signed short-lived tokens, token-only identity, decision tokens between services, signed requests | Agents use signed short-lived tokens; function tools verify single-use decision tokens |
| **ASI08** Cascading failures | One misbehaving agent floods tools or other agents | Limits per run, rate and concurrency, loop guard, burst detection, kill switch, fail closed | Calls per run limited; request rates limited; loops stopped; a kill switch is ready |
| **ASI09** Human-agent trust exploitation | A person is talked into approving something harmful | Approvals show exact parameters and bind to them, stages and two-person rules, no self-approval, expiry, reasons | Approvals bind to the action hash; more than one person reviews approvals |
| **ASI10** Rogue agents | An agent behaves outside its purpose | Rule and behavioural detection, automatic quarantine and credential revocation, incidents, the sealed audit trail | Critical threats quarantine automatically; behavioural detection is on; the audit trail is sealed and checkpointed |
