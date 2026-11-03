# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-11-02

First public release: a self-hosted security layer between AI agents and the resources
they act on. Every agent has its own identity, every action is decided by deterministic
policy before it happens, sensitive actions wait for a person, credentials stay inside
AgentGuard, untrusted code runs in a sandbox, outbound traffic goes through an egress
guard, and every decision lands in a tamper-evident log.

### Added

- **Identity**: organisations, projects, people with four dashboard roles (org admin,
  security officer, reviewer, auditor), password sign-in with lockout per account and
  address, invitations, OIDC single sign-on (PKCE, nonce, allowed domains, role mapping,
  subject binding). Agents with labels, framework, owner, project and status (active,
  suspended, quarantined, revoked); credentials exchanged at `/oauth/token` for
  short-lived Ed25519 tokens re-checked on every call; JWKS; rotation with a grace period;
  revocation; source network binding; optional signed requests with replay protection.
  Management API keys with read and write scopes.
- **Access control**: agent roles with inheritance, permissions on tool, action and
  resource patterns with optional conditions, bound to the organisation, a project or an
  agent; a resource registry with owner project, sensitivity, environment, data classes
  and tags.
- **Policy engine**: YAML policies (the brief's format, plus list rules with tools,
  resources, conditions, obligations and approvals), strict compilation with readable
  errors, a hand-parsed condition language with ranked risk levels and sensitivities,
  deny-overrides evaluation (`quarantine > deny > require_approval > restrict > allow`)
  with a deterministic specificity explanation, default deny, four built-in policies
  (project boundary, tainted-run guard, data exfiltration guard, critical actions),
  immutable versions, activation, rollback, validation, dry runs and simulation against
  recorded decisions. Optional OPA adapter that can only add caution.
- **Decision API**: `authorize`, `execute` (trusted execution of HTTP, MCP and sandbox
  tools with injected secrets), content scans, decision tokens bound to the action hash
  and redeemable once, audit mode with `would_be`, runs with call counts and taint, and
  agents asking a person before acting. Fails closed with `guard_unavailable`.
- **Tools**: a registry of HTTP, MCP, sandbox and function tools with JSON schemas,
  parameter constraints, resource templates, risk, sensitivity and external flags.
- **MCP gateway and catalog** (from MCP Hub): streamable HTTP and allowlisted stdio
  servers, discovery and health checks on a schedule, tool fingerprints with a version
  history, change and poisoned-description review, one namespaced `/mcp` endpoint that
  hides tools an agent cannot use and runs every call through the pipeline, an upstream
  connection pool with secrets injected at connect.
- **Approvals**: requests bound to the action hash with sealed parameters, ordered stages,
  role and named reviewers, N-of-M counts, no self-approval, expiry, comments, reject and
  request-changes reasons, emergency revoke, email and webhook notifications, append-only
  history, execution through the full pipeline on approval.
- **Secrets**: envelope encryption with per-version data keys wrapped by KMS or a local
  key; AWS Secrets Manager, HashiCorp Vault KV v2 and allowlisted environment stores;
  versions, rotation with a grace period and a 401 retry, expiry, revocation, host binding,
  leases, an append-only access log, and a leak check that redacts managed secrets from
  tool outputs.
- **Threat detection**: a prompt injection guard over normalised text (invisible and tag
  characters, homoglyphs, base64), spotlighting, run taint, an optional AI classifier
  (OpenAI-compatible, Ollama, Anthropic) that can only raise a verdict; data detectors with
  checksums (cards, IBANs, US SSNs, Aadhaar, PAN, emails, phones, cloud keys, tokens,
  private keys, JWTs) and redaction; rule detections for loops, bursts, permission probing,
  credential leaks, cross-tenant tokens, blocked egress, exfiltration and MCP rug pulls;
  behavioural baselines with robust z-scores and new-tool detection; automatic responses
  per severity (notify, incident, quarantine, revoke credentials).
- **Network guard**: network policies with host patterns, CIDRs, ports and methods; an
  egress forward proxy (CONNECT and plain HTTP) authenticated per agent; resolve-once
  connections and connected-peer checks against DNS rebinding; metadata addresses always
  refused; egress events with byte accounting.
- **Sandbox**: an unprivileged nsjail service for Python, Node.js and shell with CPU,
  memory, process, file, output and wall-clock limits, a read-only root, scratch tmpfs, and
  no network unless policy grants the egress proxy through a credential-holding relay.
- **Limits**: per organisation, project, agent and user limits on calls per run, run
  duration, concurrent runs, failed attempts, requests per window, data transfer and
  sandbox memory, with atomic counters, automatic suspension and a kill switch; TokenShield
  budgets with fail-open or fail-closed modes.
- **Risk engine**: scores and levels from the tool, the verb, the resource, data classes,
  external destinations, taint and the agent's history, plus organisation risk rules, with
  the factors shown.
- **Audit**: an append-only, hash-chained log sealed by one writer per organisation,
  database triggers that refuse edits and deletes, signed checkpoints exported to object
  storage, `verify` from the dashboard and the CLI, redaction, retention that keeps the
  chain verifiable, JSON lines export and SIEM forwarding.
- **Incidents and compliance**: incidents with timelines, hashed evidence, containment
  actions and Markdown and JSON exports; a signed OWASP Top 10 for Agentic Applications
  (ASI01 to ASI10) report with live evidence.
- **Integrations**: signed webhooks with retries and automatic disabling, a Python SDK
  (sync and async clients, a tool decorator, decision verification, FastAPI dependency,
  LangGraph, CrewAI and MCP helpers) and a Node.js SDK (client, verification, Express
  middleware), sharing action-hash test vectors with the server.
- **Dashboard**: overview with a live decision feed, agents, access control, policy
  builder with simulation and versions, tool security, approvals, threats, risk center,
  secrets, sandboxes, network guard, audit logs with verification, incidents, compliance,
  integrations and settings, in light and dark themes.
- **Demo**: Kestrel Labs, with five agents, tools over HTTP, MCP and the sandbox,
  policies, secrets, network policies, limits, 30 days of history and today's scenarios
  played through the real pipeline (held refunds, a tainted research run, a rug-pulled MCP
  tool, a quarantined agent and its incident).
- **Operations**: Docker Compose stack on Floci provisioned by the same Terraform as AWS;
  Terraform modules and `aws-dev` and `aws-prod` environments (ECS Fargate, the sandbox on
  ECS on EC2, RDS, ElastiCache, S3 with Object Lock, KMS, Secrets Manager, SES,
  CloudWatch); production boot guards; health, readiness and Prometheus metrics; backup
  and restore; unit, integration, backend matrix, hostile sandbox, end-to-end, browser QA,
  Terraform, sanitization, DAST and benchmark suites.

[Unreleased]: https://github.com/euron-sde-team/euron-open-agent-guard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/euron-sde-team/euron-open-agent-guard/releases/tag/v0.1.0
