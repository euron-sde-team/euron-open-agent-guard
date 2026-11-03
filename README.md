<p align="center">
  <img src="docs/assets/banner.svg" alt="Euron Open AgentGuard: secure every agent, control every action, trust every execution" width="100%">
</p>

<p align="center">
  <img alt="Open source" src="https://img.shields.io/badge/open_source-%E2%9D%A4-059669?style=flat">
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-3b82f6?style=flat"></a>
  <img alt="Python 3.12" src="https://img.shields.io/badge/Python-3.12-3776ab?style=flat&logo=python&logoColor=white">
  <img alt="FastAPI" src="https://img.shields.io/badge/FastAPI-async-009688?style=flat&logo=fastapi&logoColor=white">
  <img alt="Next.js 15" src="https://img.shields.io/badge/Next.js-15-000000?style=flat&logo=nextdotjs&logoColor=white">
  <img alt="PostgreSQL 16" src="https://img.shields.io/badge/PostgreSQL-16-4169e1?style=flat&logo=postgresql&logoColor=white">
  <img alt="MCP gateway" src="https://img.shields.io/badge/MCP-gateway-059669?style=flat">
  <img alt="Terraform" src="https://img.shields.io/badge/IaC-Terraform-7b42bc?style=flat&logo=terraform&logoColor=white">
  <img alt="AWS" src="https://img.shields.io/badge/AWS-ready-ff9900?style=flat&logo=amazonwebservices&logoColor=white">
</p>

<p align="center">
  <a href="https://github.com/euron-sde-team/euron-open-agent-guard/stargazers"><img alt="Star this repo" src="https://img.shields.io/github/stars/euron-sde-team/euron-open-agent-guard?style=social&label=Star%20this%20repo"></a>
  <a href="https://github.com/euron-sde-team/euron-open-agent-guard/fork"><img alt="Fork" src="https://img.shields.io/github/forks/euron-sde-team/euron-open-agent-guard?style=social&label=Fork"></a>
  <a href="https://github.com/euron-sde-team/euron-open-agent-guard/watchers"><img alt="Watch" src="https://img.shields.io/github/watchers/euron-sde-team/euron-open-agent-guard?style=social&label=Watch"></a>
  <br>
  <a href="https://github.com/euron-sde-team/euron-open-agent-guard/issues"><img alt="Open issues" src="https://img.shields.io/github/issues/euron-sde-team/euron-open-agent-guard?style=flat&color=059669"></a>
  <a href="https://github.com/euron-sde-team/euron-open-agent-guard/pulls"><img alt="PRs welcome" src="https://img.shields.io/badge/PRs-welcome-34d399?style=flat"></a>
  <a href="https://github.com/euron-sde-team/euron-open-agent-guard/commits/main"><img alt="Last commit" src="https://img.shields.io/github/last-commit/euron-sde-team/euron-open-agent-guard?style=flat&color=8b95a8"></a>
  <img alt="Runs locally with no AWS account" src="https://img.shields.io/badge/runs_locally-no_AWS_account_needed-064e3b?style=flat">
  <br>
  <a href="#built-by-the-team-behind-euron"><img alt="Built by the team behind Euron" src="https://img.shields.io/badge/built_by-Euron-4f46e5?style=flat"></a>
</p>

<p align="center">
  <b><a href="#-quickstart">Quickstart</a></b> ·
  <b><a href="#️-architecture">Architecture</a></b> ·
  <b><a href="docs/architecture/policy-engine.md">Policies</a></b> ·
  <b><a href="docs/guides/sdk-python.md">Python SDK</a></b> ·
  <b><a href="docs/guides/sdk-node.md">Node SDK</a></b> ·
  <b><a href="docs/api/openapi.yaml">API reference</a></b> ·
  <b><a href="#️-deploy-to-aws">Deploy</a></b> ·
  <b><a href="docs/architecture/security.md">Security</a></b> ·
  <b><a href="#-documentation">Docs</a></b>
</p>

**Euron Open AgentGuard** is an open-source, MIT-licensed, self-hosted security layer for AI
agents, part of the open-source initiative of **ENGAGESPHERE TECHNOLOGY PRIVATE LIMITED**. It
sits between your agents and everything they act on (tools, MCP servers, APIs, databases,
code, the network) and decides every action before it happens: allow it, restrict it, hold it
for a person, deny it, or quarantine the agent that asked.

AI agents now refund payments, change production data, send email and run code, and they
choose what to do from text anyone can write: a web page, a ticket, a tool's output. Agent
frameworks leave authorization to you. AgentGuard gives every agent its own identity and
puts deterministic policy, human approval, secrets, network control, sandboxing and a
tamper-evident audit trail in front of every action, for agents built with any framework.

- **A guard, not a linter.** Denied actions never reach the tool. AgentGuard runs HTTP tools,
  MCP calls and code itself, with credentials the agent never holds; tools that run in your
  own process accept only a signed, single-use decision token bound to the exact action.
- **Policy as code, decided outside the model.** YAML policies with conditions, evaluated in
  a fixed order where an explicit deny always wins; versions, rollback, a dry run, and
  simulation of a draft against the last weeks of real decisions before you activate it.
- **Approvals people can trust.** An approval is bound to a hash of the exact agent, tool,
  action, resource and parameters; change one byte and it is a new request. Two-person
  rules, stages, expiry, no approving your own request, and policy re-checked at execution.
- **Prompt injection meets permissions.** Injection detection covers hidden characters,
  homoglyphs and encoded payloads, but the defence is structural: a run that read content
  trying to instruct the agent is tainted, and its next high-risk action waits for a person
  whatever its own parameters say.
- **One governed MCP endpoint.** Every registered MCP server behind `/mcp`, tools an agent may
  not use hidden, outputs scanned, and a silently changed tool definition held for review.
- **Evidence you can verify.** A hash-chained audit log that the database refuses to edit,
  signed checkpoints, `agentguard verify`, incident reports and an OWASP agentic Top 10
  compliance report, all exportable and signed.

<p align="center">
  <img src="docs/assets/tour.gif" alt="Product tour: the security overview, a refund waiting for two approvers with its exact parameters, a research run held after reading a poisoned web page, the quarantined agent's incident, the policy builder simulating a draft, the MCP tool held for review, network guard, the audit chain verified, and the compliance report" width="100%">
</p>

> [!NOTE]
> Everything in the tour ran for real: Docker Compose on a laptop, with KMS, S3 and Secrets
> Manager emulated locally and provisioned by the same Terraform modules that build
> production. The demo company's five agents decide through the real pipeline; the tools they
> call are small local services (a CRM, a payments API, a help desk and a document store over
> MCP) so the demo runs offline. A month of history comes from the demo seed.
> `make up && make demo` reproduces it.

<h3 align="center">Built by the team behind Euron</h3>

<p align="center">Euron Open AgentGuard comes from the people who build these platforms. If you like how this repository is built, come and see what we build with it.</p>

<p align="center">
  <a href="https://euron.one"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/assets/brand/euron-dark.svg"><img src="docs/assets/brand/euron-light.svg" alt="Euron: learn the latest technologies from industry experts. Visit euron.one" width="31%"></picture></a>
  <a href="https://euronsystems.com"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/assets/brand/euron-systems-dark.svg"><img src="docs/assets/brand/euron-systems-light.svg" alt="Euron Systems: the SaaS platform for educators and creators. Visit euronsystems.com" width="31%"></picture></a>
  <a href="https://alphaeuron.com"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/assets/brand/alpha-euron-dark.svg"><img src="docs/assets/brand/alpha-euron-light.svg" alt="Alpha Euron: where school kids grow creativity and tech skills with AI. Visit alphaeuron.com" width="31%"></picture></a>
</p>

<p align="center">
  <a href="https://www.instagram.com/euron_official"><img src="https://img.shields.io/badge/Instagram-E4405F?style=flat-square&logo=instagram&logoColor=white" alt="Instagram"></a>
  <a href="https://www.linkedin.com/company/euronone/posts/"><img src="https://img.shields.io/badge/LinkedIn-0A66C2?style=flat-square&logo=linkedin&logoColor=white" alt="LinkedIn"></a>
  <a href="https://x.com/euron712"><img src="https://img.shields.io/badge/X-000000?style=flat-square&logo=x&logoColor=white" alt="X"></a>
  <a href="https://www.youtube.com/@Euron-official"><img src="https://img.shields.io/badge/YouTube-FF0000?style=flat-square&logo=youtube&logoColor=white" alt="YouTube"></a>
  <a href="https://whatsapp.com/channel/0029VaeeJwq9RZAfPW9P2l07"><img src="https://img.shields.io/badge/WhatsApp_channel-25D366?style=flat-square&logo=whatsapp&logoColor=white" alt="WhatsApp channel"></a>
</p>

---

## 📚 Table of contents

- [Why AgentGuard](#-why-agentguard)
- [At a glance](#-at-a-glance)
- [Screenshots](#️-screenshots)
- [Features](#-features)
- [Architecture](#️-architecture)
- [Tech stack](#-tech-stack)
- [Prerequisites](#-prerequisites)
- [Quickstart](#-quickstart)
- [Protect your agent](#-protect-your-agent)
- [Explore the repository](#-explore-the-repository)
- [API](#-api)
- [Configuration](#️-configuration)
- [Deploy to AWS](#️-deploy-to-aws)
- [Security model](#-security-model)
- [Performance](#-performance)
- [Testing](#-testing)
- [Documentation](#-documentation)
- [Roadmap](#️-roadmap)
- [FAQ](#-faq)
- [Contributing, security and license](#-contributing-security-and-license)

## 💡 Why AgentGuard

An agent with broad API keys and a model's judgement is one poisoned web page away from
emailing your customer list or refunding the wrong account. The fixes people reach for do
not hold: a system prompt that says "never delete" is a request, not a control; a classifier
that spots injections misses the next phrasing; a wrapper that checks permissions inside the
agent is skipped by the agent's next bug.

AgentGuard moves the control out of the agent. Every agent authenticates as itself; every
action is decided by rules a person wrote, can read and can test; the decision is enforced
where the action happens; and everything is recorded in a log nobody can quietly rewrite.
It works alone, with no other Euron product, on your own servers.

## 📊 At a glance

| | |
| --- | --- |
| **Decisions** | allow, restrict (with obligations: row limits, field redaction, spotlighting), require approval, deny, quarantine |
| **Enforcement** | `execute` (AgentGuard runs HTTP, MCP and sandbox tools), single-use Ed25519 decision tokens, the MCP gateway, the egress proxy |
| **Identity** | One identity per agent, client credentials exchanged for short-lived signed tokens, rotation with grace, revocation, signed requests with replay protection; people by password or OIDC single sign-on, five roles |
| **Policies** | YAML, deny-overrides, conditions on agent, tool, resource, parameters, risk, data classes, run taint and time; versions, rollback, dry run, simulation; optional OPA that can only add caution |
| **Protection** | Prompt injection guard with evasion handling, run taint, personal data and credential detection (checksum validated), DLP, risk scoring, behavioural anomaly detection, automatic quarantine |
| **Secrets** | Envelope encryption (KMS or a local key), AWS Secrets Manager, Vault, environment; never returned, injected at execution, bound to hosts, leases, rotation without downtime |
| **Containment** | Unprivileged nsjail sandbox, egress proxy with per-agent network policy, execution limits, kill switch, incidents |
| **SDKs** | Python (sync and async, FastAPI, LangGraph, CrewAI, MCP) and Node.js (Express); any MCP client |
| **Infrastructure** | 11 Terraform modules, 3 environments; the full AWS stack applied end to end against Floci |
| **Tests** | 516 (171 unit, 83 integration, 44 sandbox, 67 web, 94+36 Python SDK, 63+8 Node SDK) |
| **License** | MIT |

## 🖼️ Screenshots

<table>
  <tr>
    <td width="50%"><img src="docs/assets/screenshots/00-sign-in.png" alt="Sign in"><br><sub><b>Sign in.</b> Password or an organisation's own single sign-on; no demo data visible before authentication.</sub></td>
    <td width="50%"><img src="docs/assets/screenshots/01-overview.png" alt="Overview"><br><sub><b>Overview.</b> Decisions, pending approvals, open threats and incidents, blocked connections, latency and the riskiest agents, all last 24 hours.</sub></td>
  </tr>
  <tr>
    <td><img src="docs/assets/screenshots/02-agents.png" alt="Agents"><br><sub><b>Agents.</b> Every registered workload, its status, role and recent activity.</sub></td>
    <td><img src="docs/assets/screenshots/03-agent-detail.png" alt="Agent detail"><br><sub><b>Agent detail.</b> Credentials, roles, labels, network policy and the agent's own decision log.</sub></td>
  </tr>
  <tr>
    <td><img src="docs/assets/screenshots/04-policy-builder.png" alt="Policy builder"><br><sub><b>Policy builder.</b> Scope, rules and conditions over YAML, with a visual editor and live validation.</sub></td>
    <td><img src="docs/assets/screenshots/05-policy-simulate.png" alt="Policy simulate"><br><sub><b>Simulate.</b> A draft policy replayed against real recorded decisions before it is ever active.</sub></td>
  </tr>
  <tr>
    <td><img src="docs/assets/screenshots/06-approval-detail.png" alt="Approval detail"><br><sub><b>Approval detail.</b> The exact parameters bound by hash, who may approve, and an append-only history.</sub></td>
    <td><img src="docs/assets/screenshots/07-threats.png" alt="Threat detection"><br><sub><b>Threat detection.</b> Rule and behavioural detections with severity and the automatic response taken.</sub></td>
  </tr>
  <tr>
    <td><img src="docs/assets/screenshots/08-tool-review.png" alt="Tool review"><br><sub><b>Tool review.</b> A changed MCP tool description, diffed, with the injected instruction it tried to hide.</sub></td>
    <td><img src="docs/assets/screenshots/09-secrets.png" alt="Secrets"><br><sub><b>Secrets.</b> Metadata only; values are written once and never read back.</sub></td>
  </tr>
  <tr>
    <td><img src="docs/assets/screenshots/10-network.png" alt="Network guard"><br><sub><b>Network guard.</b> Per-agent destination rules and the connection log, metadata addresses always refused.</sub></td>
    <td><img src="docs/assets/screenshots/11-audit.png" alt="Audit log"><br><sub><b>Audit log.</b> The tamper-evident hash chain, verified live from this screen.</sub></td>
  </tr>
  <tr>
    <td><img src="docs/assets/screenshots/12-incident-detail.png" alt="Incident detail"><br><sub><b>Incident detail.</b> Timeline, evidence, containment actions and the resolution, exportable as Markdown or JSON.</sub></td>
    <td><img src="docs/assets/screenshots/13-compliance.png" alt="Compliance"><br><sub><b>Compliance.</b> OWASP ASI01 to ASI10 mapped to live evidence, signed.</sub></td>
  </tr>
  <tr>
    <td><img src="docs/assets/screenshots/14-integrations.png" alt="Integrations"><br><sub><b>Integrations.</b> SDK snippets with the real base URL, the MCP gateway, OPA, SIEM and webhooks.</sub></td>
    <td><img src="docs/assets/screenshots/15-overview-dark.png" alt="Dark mode"><br><sub><b>Dark mode.</b> Every screen, in both themes.</sub></td>
  </tr>
  <tr>
    <td><img src="docs/assets/screenshots/16-approval-detail-dark.png" alt="Approval detail, dark"><br><sub><b>Approval detail, dark mode.</b> Same binding, same history, full contrast.</sub></td>
    <td><img src="docs/assets/screenshots/17-approvals-phone.png" alt="Approvals, phone width"><br><sub><b>Phone width.</b> Responsive down to 390px, minimal boxes throughout.</sub></td>
  </tr>
</table>

## ✨ Features

#### 🪪 Agent identity and access

- Register agents with labels, owner and project; issue credentials (shown once), rotate them
  with an overlap, restrict them to networks, revoke them; suspend, quarantine or retire an
  agent and every token stops working on the next call.
- Roles with inheritance bound to the organisation, a project or one agent; permissions on
  tool patterns, actions, resource patterns and conditions; projects as hard boundaries.

#### 📜 Policies you can test before they bite

- The policy builder edits YAML visually or as text; every rule explains itself in the
  decision log, with the policy version that decided it.
- Dry-run any request against a draft, or simulate the draft against recorded decisions and
  see exactly which past actions would change.
- Built-in guard policies (project boundary, tainted runs, data exfiltration, critical risk)
  that you can tune but not silently bypass.

#### 🧑‍⚖️ Human approval

- Bound to the exact action; reviewers see the exact parameters; N of M reviewers, stages,
  roles or named people; expiry, comments, request changes, emergency revoke; email and
  webhook notifications; AgentGuard runs approved HTTP, MCP and sandbox actions itself after
  checking policy again.

#### 🛡️ Threats, data and the network

- Injection scanning of tool outputs, MCP results and content agents read, with automatic
  spotlighting; run taint; detectors for cards, IBANs, Aadhaar, PAN, SSNs, emails, phones and
  credentials; loops, bursts, permission probing, exfiltration and behavioural anomalies.
- Automatic responses by severity: quarantine, revoke credentials, open an incident, notify.
- An egress proxy that only lets each agent reach what its network policy allows; metadata
  and private addresses refused even after DNS rebinding.

#### 🧾 Audit, incidents, compliance

- Hash-chained audit records, database rules that refuse edits and deletes, signed
  checkpoints exported to object storage, retention that keeps the chain verifiable.
- Incidents with timelines, hashed evidence, containment actions and Markdown or JSON reports.
- A signed OWASP Top 10 for Agentic Applications report with live evidence per risk.

## 🏗️ Architecture

<p align="center">
  <img src="docs/assets/diagrams/architecture.svg" alt="Architecture: agents and MCP clients, the API with the decision pipeline and the MCP gateway, the worker, the egress proxy, the sandbox, Postgres, Redis, KMS and object storage" width="100%">
</p>

The API decides and records every action in one Postgres transaction. Policies, permissions
and the configuration a decision reads are cached per process under a generation counter
that every change bumps, so a deactivated policy stops applying on the next decision on every
replica. The worker runs approvals, notifications, MCP discovery, behavioural detection,
audit sealing and retention from a Postgres outbox. The sandbox and the egress proxy are
separate services: untrusted code never runs in the API, and agents reach the network only
through the proxy.

### The decision pipeline

<p align="center">
  <img src="docs/assets/diagrams/decision-pipeline.svg" alt="The decision pipeline: identity, kill switch, tool and parameter validation, resource, run and data classes, limits and loop guard, risk, policies and permissions, approvals, then allow, restrict, require approval, deny or quarantine" width="100%">
</p>

### Where decisions are enforced

<p align="center">
  <img src="docs/assets/diagrams/enforcement-points.svg" alt="Enforcement points: execute, decision token verification at the tool, the MCP gateway and the egress proxy" width="100%">
</p>

[High-level design](docs/architecture/HLD.md) · [Low-level design](docs/architecture/LLD.md) · [Policy engine](docs/architecture/policy-engine.md)

## 🧰 Tech stack

| Layer | Choice |
| --- | --- |
| API, worker, egress proxy | Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2 async, Alembic, uv |
| Sandbox | nsjail in an unprivileged container (user namespaces, rlimits, seccomp) |
| Data | PostgreSQL 16, Redis 7 (optional) |
| Crypto | Ed25519 (tokens, checkpoints, reports), AES-256-GCM envelope encryption, KMS |
| Integrations | MCP SDK 2.x, Open Policy Agent, HashiCorp Vault, AWS Secrets Manager, OIDC, TokenShield |
| Web | Next.js 15, React 19, TypeScript, Tailwind v4, shadcn/ui, TanStack Query |
| SDKs | Python (httpx, PyJWT), Node.js (TypeScript, jose) |
| Infrastructure | Docker Compose, Floci (local AWS), Terraform (ECS Fargate, ECS on EC2 for the sandbox, RDS, ElastiCache, S3 with Object Lock, KMS, Secrets Manager, SES, Cloud Map, CloudWatch) |
| Tests | pytest, Hypothesis, Vitest, Playwright, Puppeteer, checkov, tflint, OWASP ZAP |

## 📋 Prerequisites

- Docker with Compose v2 (that is all the stack needs)
- For running tests outside containers: [uv](https://docs.astral.sh/uv/) and Node.js 20 with pnpm

## 🚀 Quickstart

```bash
git clone https://github.com/euron-sde-team/euron-open-agent-guard.git
cd euron-open-agent-guard
make env     # local secrets in deploy/compose/.env
make up      # Postgres, Redis, Floci, OPA, Vault, Mailpit, API, worker, egress, sandbox, web
make demo    # "Kestrel Labs": five agents, tools, policies, secrets and a month of history
```

Then open http://localhost:5110 and sign in as `nora@kestrel.example` (organisation
administrator) with `Demo-Pass-2026`. Other demo people: `omar@` (security officer), `priya@`
and `daniel@` (reviewers), `elena@` (auditor), all `@kestrel.example`. Mail lands in Mailpit
at http://localhost:5125.

## 🔌 Protect your agent

```python
from euron_agentguard import AgentGuard

guard = AgentGuard("http://localhost:5130", client_id="ag_...", client_secret="ags_...")

decision = guard.authorize("payments.refund", "refund",
                           parameters={"customer_id": "1024", "amount": 450, "currency": "EUR"})
if decision.needs_approval:
    decision = decision.wait_for_approval(timeout=600)   # a reviewer decides in the dashboard

# Or let AgentGuard run the tool itself (the payments key never reaches the agent):
result = guard.execute("payments.refund", "refund", parameters={...})
```

Wrap LangGraph or CrewAI tools, protect a FastAPI tool with decision-token verification in
three lines, or point any MCP client at `http://localhost:5130/mcp` with the agent's token.
[Python SDK](docs/guides/sdk-python.md) · [Node SDK](docs/guides/sdk-node.md) · [Frameworks](docs/guides/frameworks.md) · [Examples](examples/)

## 🧭 Explore the repository

| Path | What is there |
| --- | --- |
| [`apps/api/src/agentguard/decisions/`](apps/api/src/agentguard/decisions) | The decision pipeline, execution adapters, output processing, decision tokens |
| [`apps/api/src/agentguard/policies/`](apps/api/src/agentguard/policies) | The policy language, compiler, engine, built-in policies, simulation |
| [`apps/api/src/agentguard/approvals/`](apps/api/src/agentguard/approvals) | Approval requests, votes, stages, history |
| [`apps/api/src/agentguard/protection/`](apps/api/src/agentguard/protection) | Injection guard and personal data and credential detectors |
| [`apps/api/src/agentguard/mcp/`](apps/api/src/agentguard/mcp) | MCP catalog, discovery, upstream pool and the `/mcp` gateway |
| [`apps/api/src/agentguard/network/`](apps/api/src/agentguard/network) | Network policies and the egress proxy |
| [`apps/api/src/agentguard/audit/`](apps/api/src/agentguard/audit) | The hash chain, sealing, verification, checkpoints |
| [`apps/api/src/agentguard_sandbox/`](apps/api/src/agentguard_sandbox) | The sandbox service (nsjail runner and network relay) |
| [`apps/web/`](apps/web) | The dashboard |
| [`sdks/python/`](sdks/python), [`sdks/node/`](sdks/node) | The SDKs and framework integrations |
| [`examples/`](examples) | Runnable examples: quickstart, LangGraph, FastAPI, Node, MCP |
| [`infra/terraform/`](infra/terraform) | Modules and the `local-floci`, `aws-dev`, `aws-prod` environments |

## 🔌 API

The OpenAPI document is [docs/api/openapi.yaml](docs/api/openapi.yaml) (161 operations);
the running API serves it at http://localhost:5130/docs. Agents call `/oauth/token`,
`/api/v1/authorize`, `/api/v1/execute`, `/api/v1/content/scan` and `/mcp`; tools verify
decision tokens with `/api/v1/decisions/redeem` or offline with `/.well-known/jwks.json`.
Webhooks carry `X-AgentGuard-Signature: t=<unix>,v1=<hex>` (HMAC-SHA256 of `<t>.<body>`).

## ⚙️ Configuration

Deployment settings are environment variables ([full reference](docs/guides/configuration.md));
each organisation's enforcement mode, default decision, detection, threat responses,
retention and notifications are edited in Settings. Production refuses to boot with demo
secrets, insecure cookies, a wildcard CORS origin, private URL access, or private AI
endpoints while anyone may sign up.

## ☁️ Deploy to AWS

`infra/terraform/envs/aws-dev` and `aws-prod` build ECS Fargate services (api, worker, web,
egress) behind an ALB with WAF, the sandbox on EC2 hosts of its own with a seccomp profile and
no instance credentials, RDS PostgreSQL, ElastiCache, S3 with an Object Lock bucket for audit
checkpoints, KMS, Secrets Manager, SES, Cloud Map and CloudWatch alarms. Nothing here has been
applied to a real AWS account; the whole environment is planned, applied, re-planned and
destroyed against Floci by `make tf-aws-on-floci`. [Deploy guide](docs/guides/deploy-aws.md)

## 🔐 Security model

- **No agent is trusted by name.** Identity comes only from the agent's own credential; a
  self-reported name in a request is refused.
- **Fail closed.** If AgentGuard cannot decide (its database is down), the answer is deny, and
  the SDKs treat any error as deny.
- **The model never makes the decision.** Policies, permissions, limits and approvals are
  deterministic; detectors and the optional AI classifier can only add caution.
- **Secrets stay inside.** Values are never returned, encrypted per version, injected only into
  destinations they are bound to, and redacted when a tool echoes them back.
- **Tenants are isolated** structurally in every query, and the suites check cross-tenant
  reads, writes, approvals and tokens are refused.
- **History is tamper-evident.** Edits and deletes are refused by the database; a superuser who
  disables that is caught by `verify` and by the signed checkpoints.

[Security](docs/architecture/security.md) · [Threat model](docs/architecture/threat-model.md)

## ⚡ Performance

From a real local run (`make bench`, [docs/bench.json](docs/bench.json)). The policy engine
number is the one that does not depend on the machine's own load; the end-to-end numbers
below were measured on a busy development machine (load average ~17 on 12 CPUs) alongside
other work, so treat them as upper bounds, not a dedicated-hardware baseline.

| Measurement | Result |
| --- | --- |
| Policy engine only, 50 policies | 96 microseconds per decision |
| `authorize` end to end (database, cache, risk, policy, audit) | p50 25ms, p95 151ms, p99 230ms |
| `authorize` throughput, 50 concurrent agents | 116 decisions/s |
| `execute` on an HTTP tool, overhead over a direct call | p50 +18ms |
| Audit sealing | 7,303 records/s |
| Audit chain verification | 15,251 records/s |

## 🧪 Testing

| Suite | Count | Run |
| --- | --- | --- |
| API unit | 171 | `make test` |
| API integration | 83 | `make test-integration` |
| API integration matrix (8 combinations: local/KMS keys, database/Vault secrets, Redis on/off) | 83 x 8 | `make test-matrix` |
| Sandbox (hostile suite, inside the sandbox image) | 44 | `make test-sandbox` |
| Python SDK | 94 unit + 36 integration | `cd sdks/python && uv run pytest` |
| Node SDK | 63 unit + 8 integration | `cd sdks/node && pnpm test` (`pnpm test:integration` against a running stack) |
| Web unit (Vitest) | 67 | `cd apps/web && pnpm test` |
| End to end (Playwright) | see `e2e/tests` | `make e2e` |
| Browser QA (Puppeteer, every page, light/dark, desktop/phone) | - | `make qa` |

Static: `ruff check`, `ruff format --check`, `mypy --strict` (166 files, clean), `eslint`,
`tsc --noEmit`. Line coverage on `apps/api/src`: 86% (`make test` with `--cov`).

## 📖 Documentation

| Architecture | Guides |
| --- | --- |
| [High-level design](docs/architecture/HLD.md) | [Quickstart (local)](docs/guides/quickstart-local.md) |
| [Low-level design](docs/architecture/LLD.md) | [Product walkthrough](docs/guides/walkthrough.md) |
| [Policy engine](docs/architecture/policy-engine.md) | [Writing policies](docs/guides/writing-policies.md) |
| [Approvals](docs/architecture/approvals.md) | [Python SDK](docs/guides/sdk-python.md), [Node SDK](docs/guides/sdk-node.md) |
| [Identity](docs/architecture/identity.md) | [Frameworks (LangGraph, CrewAI, MCP, FastAPI)](docs/guides/frameworks.md) |
| [Secrets](docs/architecture/secrets.md) | [Configuration reference](docs/guides/configuration.md) |
| [Threat detection](docs/architecture/threat-detection.md) | [Deploy to AWS](docs/guides/deploy-aws.md) |
| [MCP gateway](docs/architecture/mcp-gateway.md), [network guard](docs/architecture/network-guard.md) | [Local against real AWS](docs/guides/local-with-aws.md) |
| [Sandbox](docs/architecture/sandbox.md), [audit](docs/architecture/audit.md) | [Operations runbook](docs/guides/operations.md) |
| [Data model](docs/architecture/data-model.md) | [Testing](docs/guides/testing.md) |
| [Security](docs/architecture/security.md), [threat model](docs/architecture/threat-model.md) | [Troubleshooting](docs/guides/troubleshooting.md) |
| [Decision records](docs/architecture/adr/), [API reference](docs/api/openapi.yaml) | [Build plan](docs/PLAN.md), [changelog](CHANGELOG.md) |

## 🗺️ Roadmap

- gVisor, Firecracker and Kubernetes sandbox backends (the adapter interface ships today)
- mTLS and SPIFFE workload identity for agents
- Relationship-based access (ReBAC) and access review campaigns
- Approval buttons in Slack and Microsoft Teams
- PyPI and npm releases of the SDKs; a Helm chart
- Guarding model calls inside the agent (today AgentGuard governs actions and TokenShield governs model spend)

Have an idea? [Open a feature request](https://github.com/euron-sde-team/euron-open-agent-guard/issues/new/choose).

## ❓ FAQ

**Does it need Euron AgentOS or any other Euron product?** No. It works with any agent that
can make an HTTP call or speak MCP. TokenShield is an optional integration for model budgets.

**Will it slow my agent down?** A decision is a few milliseconds of AgentGuard's own time (see
Performance); a call AgentGuard executes adds that plus one local hop.

**Can I roll it out without breaking anything?** Yes: audit mode allows every action and
records what enforce mode would have decided, so you can tune policies on real traffic first.

**What if an injection gets past the detector?** The run's next high-risk action still needs a
person if any content it read was flagged, permissions still apply, and the tool still only
accepts what policy allowed. The detector is one signal, not the defence.

**Is it production ready?** It is built and tested to production standards locally, with the
AWS Terraform validated and applied against an emulator. It has not been run by us on a real
AWS account, and it has not had an independent security review yet; read the
[operator checklist](docs/architecture/security.md) first.

## 🤝 Contributing, security and license

Contributions are welcome: read [CONTRIBUTING.md](CONTRIBUTING.md) and the
[code of conduct](CODE_OF_CONDUCT.md). Report security issues privately as described in
[SECURITY.md](SECURITY.md).

Released under the [MIT License](LICENSE). Copyright (c) 2026 ENGAGESPHERE TECHNOLOGY
PRIVATE LIMITED and the Euron Open AgentGuard contributors.

<p align="center">
  If AgentGuard keeps your agents in line, <b><a href="https://github.com/euron-sde-team/euron-open-agent-guard/stargazers">⭐ star the repository</a></b>.
</p>
