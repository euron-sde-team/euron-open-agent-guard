# Testing

Every gate runs locally against Docker; nothing needs an AWS account or an API key.

| Gate | Command | Needs |
| --- | --- | --- |
| Static | `make lint typecheck` | uv, pnpm |
| Unit | `make test` | nothing running |
| Integration | `make test-integration` | Postgres, Redis, OPA, Vault, sandbox and mockai (started for you) |
| Backend matrix | `make test-matrix` | `make up` (Floci for KMS) |
| Sandbox (hostile suite) | `make test-sandbox` | Docker (builds the sandbox image) |
| SDKs | `uv run pytest` in `sdks/python`, `pnpm test` in `sdks/node` | the integration suites need the stack |
| OpenAPI drift | part of `make test` | nothing |
| End to end | `make e2e` | `make up && make demo` |
| Browser QA | `make qa` | `make up && make demo` |
| Infrastructure | `make tf-validate tf-lint tf-security tf-aws-on-floci` | Docker |
| Sanitization | `make sanitize` | nothing |
| DAST | `make dast` | `make up` |
| Benchmarks | `make bench` | Postgres and Redis (the bench uses its own database) |

Test counts at release 0.1.0: 171 API unit, 83 API integration (x8 under `make test-matrix`),
44 sandbox, 67 web unit, 94 Python SDK unit + 36 integration, 63 Node SDK unit + 8 integration.
Line coverage of `apps/api/src` from unit plus integration: 86%.

## Unit tests

`apps/api/tests/unit/` needs no database or network.

- `test_policy_engine.py`: the expression language (every operator, functions, level and
  sensitivity ranks, readable syntax errors, evaluation errors, paths), compiling the
  brief's policy and deciding with it, readable policy errors, deny over allow regardless
  of order, permissions only when no rule matches, broken conditions that can deny but
  never grant, merged obligations, the strictest approval and the specificity
  explanation, scopes by agent, role, label, project, environment and framework, MCP
  visibility ignoring organisation-wide guards, the built-in policies, and two
  Hypothesis property tests: the strongest decision wins whatever the order, and
  evaluation is a pure function.
- `test_protection.py`: data detectors with their checksums and the lookalikes they must
  not report, JSON walking and credential-named keys, redaction, the injection corpus
  with evasions (zero-width and tag characters, base64, homoglyphs, markdown image
  exfiltration) and benign text, normalisation, spotlighting that the content cannot
  close, risk levels and factors, the canonical action hash (formatting ignored, any
  change caught), network rules, parameter validation and resource templates, every
  production boot guard, and defensive parsing of classifier answers.
- `test_sandbox_service.py`: the sandbox service's wire contract with the API client,
  token checks, body limits, validation that never echoes values, limits above the
  service maximum, the nsjail command line, the proxy relay's request rewriting,
  supervision of output floods and wall clocks, and the development fallback.

The web app's Vitest suite (`apps/web/test/`) covers the API client and error mapping,
live-event parsing and query invalidation, and formatting. The SDKs have their own unit
suites (`sdks/python/tests/unit`, `sdks/node/test/unit`): the canonical hash against the
shared vectors in `sdks/testdata/action-hash-vectors.json`, the clients' fail-closed
behaviour, token refresh, decorators and framework wrappers, and offline verification.

The OpenAPI drift test compares `docs/api/openapi.yaml` with the live app; regenerate it
with `make openapi` when you change an endpoint.

## Integration tests

`make test-integration` makes sure the Compose services it needs are reachable
(`scripts/test-db.sh`), then runs `apps/api/tests/integration` with coverage.

How the harness works (`tests/integration/conftest.py`):

- **Real processes.** The real API (uvicorn), the real worker and the mock services each
  run on their own thread and event loop, against real Postgres and Redis, and real OPA,
  Vault, the sandbox and Floci when their URLs are given.
- **Isolation by tenant.** Every test signs up its own organisation, which also exercises
  tenant scoping on every request.
- **Real migrations.** The test database is dropped and rebuilt by the Alembic migrations
  once per run.
- **Guarded.** The suite refuses a database whose name does not contain `test`, and any
  non-local host unless `ALLOW_REMOTE_TEST_DB=true`.

What the files cover, one test per acceptance criterion and more:

| File | Covers |
| --- | --- |
| `test_decisions.py` | The brief's policy, organisation scopes, deny overrides, default deny, role inheritance, parameter validation first, the project boundary, versions, activation, rollback and the version on every decision, simulation, dry runs, restrict obligations applied by execution, a denied action never reaching the tool, decision tokens (bound, single use, verifiable), function tools not executable, identity from the token only, revoked and rotated credentials, suspended, quarantined and revoked agents, signed requests and replays, token exchange rate limits, fail closed with the database down, body limits, concurrent authorizations |
| `test_approvals_secrets.py` | Approved actions run once through AgentGuard, two-person rules, no self-approval, binding to exact parameters, rejection reasons and changes, expiry and revocation, policy changes after approval, email and webhook notifications, append-only history, secret values never leaving, rotation grace, refused secrets (revoked, expired, no lease, wrong host), a tool echoing its credential, the Vault store |
| `test_protection.py` | Content scans tainting runs and holding the next risky action, injected tool outputs, the AI classifier raising but never lowering, classified data to external tools, loops, bursts and permission probing, critical threat responses (quarantine, revoke, incident), limits under concurrency, calls per run and concurrent runs, automatic suspension, the kill switch within a second, TokenShield budgets and its fail-open mode |
| `test_mcp_network.py` | One MCP endpoint listing only usable tools, tokens required, scanned outputs tainting runs, changed tool definitions held for review, stdio allowlists and metadata URLs, the egress proxy enforcing network policy, suspended agents refused by the proxy, HTTP tools following the agent's network policy |
| `test_governance.py` | The audit chain verifying and refusing edits, tampering detected with the database rules off, checkpoints and retention, the incident lifecycle and exports, the OWASP compliance report, tenant isolation, dashboard roles, OIDC sign-in, OPA adding caution only, the CSRF header |
| `test_security.py` | Cross-tenant approval ids, agent tokens kept out of the management API, people raising their own role, expired credentials, forged and tampered approvals, secrets absent from logs, SSRF through tool configuration, code running only in the sandbox |

## The backend matrix

`make test-matrix` reruns the integration suite under every backend combination:

| Dimension | Values |
| --- | --- |
| Keys | local key file (AES-GCM), AWS KMS (Floci) |
| Secret store | database (envelope encrypted), HashiCorp Vault KV v2 |
| Redis | on (shared counters, nonces, fan-out), off (in process) |

Eight runs, each in its own test database. It needs `make up` for the KMS key the
`local-floci` Terraform created.

## The sandbox suite

`make test-sandbox` (`scripts/test-sandbox.sh`) builds the sandbox image and runs
`apps/api/tests/sandbox` **inside it**, with exactly the hardening production gives the
service: every capability dropped, no new privileges, the custom seccomp profile, a
read-only root, tmpfs scratch, process and memory limits, no network. It covers every
language, scratch files, the environment, exit codes and crashes, exact CPU and memory
measurement, and the hostile programs: fork and thread bombs (and that they do not starve
a concurrent run), killing everything, memory bombs, CPU spins, sleepers, programs blocked
on stdin, output floods, file growth, scratch limits, writes outside scratch, reading host
and service files, finding the service token, namespace, mount and ptrace calls, spawned
shells, reverse shells, network in mode `none`, the proxy relay (the program cannot read
the credential, only the proxy is reachable), and the service surviving a burst of hostile
runs. Extra arguments go to pytest: `scripts/test-sandbox.sh -k proxy`. See
[sandbox.md](../architecture/sandbox.md#running-the-hostile-suite).

## End to end

- `make e2e` runs the Playwright journeys in `e2e/` against `make up && make demo`: the
  five-minute path (sign in, see the agents, approve a held payment and watch it execute),
  approvals with two reviewers, an incident from a quarantined agent, roles and tenancy,
  and the policy builder (write, simulate, activate, see the next decision follow it).

## Browser QA

`make qa` runs `scripts/qa/qa.mjs` (Puppeteer, Chromium): every page in light and dark
mode at desktop and phone width; it fails on console errors, failed requests, broken
images, horizontal overflow or empty unexplained states, and saves screenshots.
`make screenshots` produces the curated set in `docs/assets/screenshots/` and the tour GIF.

## Infrastructure

`make tf-validate tf-lint tf-security` validates, lints (tflint) and scans (checkov) every
module and environment. `make tf-aws-on-floci` plans, applies, re-plans (no additions or
replacements allowed) and destroys the full `aws-dev` environment against a throwaway
Floci on port 5196.

## Sanitization and DAST

`make sanitize` (`scripts/check-sanitization.sh`) fails on credentials, private keys,
cloud account and resource ids, AWS host names, committed env files or Terraform state, and
em or en dashes. `make dast` runs the OWASP ZAP API scan against the running API's OpenAPI
document and writes `reports/dast/report.html`.

## Benchmarks

`make bench` runs `apps/api/bench.py` against a throwaway `agentguard_bench` database:
`authorize` latency (sequential) and throughput (50 concurrent agents), the policy engine
alone with 50 active policies, `execute` of an HTTP tool against calling the tool
directly, and audit sealing and verification throughput. Results go to `docs/bench.json`
with the machine's CPU count and load.

| Measure | Result |
| --- | --- |
| `authorize` p50 / p99 | 25ms / 230ms |
| `authorize` throughput, 50 concurrent agents | 116 decisions/s |
| Policy engine, 50 policies | 96 microseconds per decision |
| `execute` overhead over a direct HTTP call | +18ms (p50) |
| Audit sealing | 7,303 records/s |
| Audit chain verification | 15,251 records/s |

These end-to-end numbers (everything except the policy-engine-only row) were measured on a
busy development machine alongside other work (load average ~17 on 12 CPUs); they are an
upper bound, not a dedicated-hardware baseline. `make bench` does not separately measure
the MCP gateway, the egress proxy or sandbox start time.
