# Security Policy

AgentGuard is a security layer: it decides what AI agents may do, holds the credentials of
the tools they use, runs untrusted code and keeps the evidence. A weakness in it is a
weakness in everything behind it. We take reports seriously and respond quickly.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.x (latest minor) | Yes |
| Older minors | No |

## Reporting a vulnerability

**Please do not open a public issue for security issues.**

Report privately through GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository ("Security" tab, "Report a vulnerability").

Please include:

- the affected component (`apps/api` and which domain, the egress proxy, the sandbox
  service, the MCP gateway, `apps/web`, `sdks/python`, `sdks/node`, `infra/terraform/...`)
  and the version or commit;
- a description of the issue and its impact;
- steps to reproduce or a proof of concept: the policy YAML, the tool and agent
  configuration, the organisation settings (enforce or audit mode), and the requests;
- any suggested mitigation.

What to expect:

| Stage | Target |
| ----- | ------ |
| Acknowledgement | within 3 business days |
| Initial assessment and severity | within 7 business days |
| Fix or mitigation for critical and high issues | within 30 days |
| Coordinated public disclosure | after a fix is released, credited to you unless you prefer otherwise |

## What counts as a vulnerability

For a security product, a vulnerability is anything that breaks one of its guarantees
([docs/architecture/security.md](docs/architecture/security.md#what-agentguard-guarantees)).
We are especially interested in:

- **Enforcement bypass**: an action that policy denies, or that requires approval,
  reaching a tool through `execute`, the MCP gateway, a verified decision token or the
  egress proxy; an approved action running with different parameters or more than once; an
  approval surviving a policy that now denies.
- **Policy evaluation flaws**: an allow beating an explicit deny, an evaluation error that
  grants, non-deterministic decisions, a policy scoped to one organisation applying to
  another.
- **Identity**: acting as another agent or organisation; a revoked, expired or rotated-out
  credential still working; a replayed signed request accepted; a forged agent, decision
  or proxy token; a reviewer approving their own request or passing a two-person rule
  alone.
- **Secrets**: recovering a managed secret's value from any API response, log line, audit
  record, error, approval preview or decision; sending a secret to a host outside its
  `allowed_hosts`; using a secret without a required lease.
- **Network**: reaching cloud metadata, private ranges (without an explicit CIDR rule) or
  any destination outside the network policy through the egress proxy, an HTTP tool, an
  MCP upstream, a webhook, the SIEM forwarder or the classifier, including through DNS
  rebinding, redirects or alternative IP spellings.
- **Sandbox escape**: code reading host or service files, reaching the network in mode
  `none`, reaching anything but the egress proxy in mode `proxy`, reading the proxy
  credential, or starving other runs beyond the documented limits.
- **Audit integrity**: editing, removing or reordering audit records (or approval history,
  the secret access log, checkpoints) without `verify` reporting it, through the
  application's own database role.
- **Fail-open behaviour**: any condition in which AgentGuard allows an action in enforce
  mode because a dependency (Postgres, Redis, OPA, the sandbox) failed.
- **Tenant isolation**: reading or changing another organisation's agents, policies,
  decisions, approvals, secrets, threats or audit records.
- **Dashboard and API**: authentication or authorization bypasses, role escalation, CSRF,
  stored XSS, SSRF, request smuggling into the egress proxy.
- **Detection evasion with impact**: a prompt injection technique that the documented
  normalisation should cover (zero-width or tag characters, base64, homoglyphs, markdown
  image exfiltration) and that leads to a high-risk action without a person.

## Out of scope

- **The demo seed.** `make demo` creates well-known demo accounts with a published
  password, on purpose.
- **The mock services** (`apps/api/src/mockai`), a test and demo fixture never deployed to
  AWS.
- **Detection misses on their own.** A phrasing the injection heuristics do not flag is a
  quality issue, not a vulnerability, unless it defeats a documented guarantee (run taint
  is the defence, not the detector). Please still send good evasions as regular issues.
- **Advisory use.** An agent that calls `authorize` and then ignores the answer is not
  stopped; that is documented. Tools that hold their own credentials or do not verify
  decision tokens are outside AgentGuard's enforcement.
- Known limitations documented in
  [docs/architecture/security.md](docs/architecture/security.md#what-agentguard-does-not-guarantee)
  and [docs/architecture/threat-model.md](docs/architecture/threat-model.md).
- Administrators abusing administrator powers (an org admin can change policies and
  settings by design; every change is audited).
- Findings that need a compromised host, a compromised cloud account, a database superuser,
  or leaked deployment secrets (`SESSION_SECRET`, `TOKEN_PEPPER`, `LOCAL_MASTER_KEY`,
  `SANDBOX_TOKEN`).
- Kernel vulnerabilities that escape any container sandbox.
- Denial of service through resource exhaustion of a deployment you operate yourself.

## Hardening checklist for operators

See [docs/architecture/security.md](docs/architecture/security.md#operator-checklist).
