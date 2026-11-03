# Contributing

Thanks for helping improve Euron Open AgentGuard. This guide covers the workflow, the bar a
change has to clear, and the conventions the codebase follows.

## Ground rules

- **Open an issue first** for anything larger than a bug fix or a docs tweak, so we can
  agree on the approach before you invest time.
- **One concern per pull request.** A refactor and a feature are two PRs.
- **Security issues go through private reporting**, never a public issue. That includes
  any way to get an action past AgentGuard that policy should have denied or held, to read
  a secret value, to act as another agent or organisation, or to reach internal addresses.
  See [SECURITY.md](SECURITY.md).
- By contributing you agree your work is released under the [MIT License](LICENSE).

## Development setup

Requirements: Docker, Python 3.12 with [uv](https://docs.astral.sh/uv/), Node 22 and
pnpm 9 (`corepack enable`).

```bash
make up          # Postgres, Redis, Floci (provisioned by Terraform), OPA, Vault, Mailpit, mock services, api, worker, egress, sandbox, web
make demo        # Kestrel Labs: five agents, tools, policies, secrets, approvals, threats and incidents
make test        # unit tests (API and web)
```

[docs/guides/quickstart-local.md](docs/guides/quickstart-local.md) walks through the local
stack in detail.

## Before you open a pull request

Each of these must pass:

```bash
make lint typecheck test
make test-integration                  # the API, worker and mock services against real Postgres, Redis, OPA, Vault and the sandbox
make test-matrix                       # when you touched keys, secret stores, counters or caches
make test-sandbox                      # when you touched the sandbox service, its image or its seccomp profile
make e2e                               # when you touched a dashboard flow
make tf-validate tf-lint tf-security   # when you touched infra/terraform
make tf-aws-on-floci                   # same: apply and destroy aws-dev against Floci
make openapi                           # when you changed an endpoint (the drift test checks it)
make sanitize                          # no credentials, account ids, hostnames or dashes
```

Changes to the SDKs run their own suites: `uv run pytest` in `sdks/python` and
`pnpm test` in `sdks/node`.

## Conventions

**Package by domain.** `apps/api/src/agentguard/<domain>/` owns its `router.py` (HTTP
only), its service module (rules and queries) and `models.py`. Dependencies point inward.
A domain calls another domain's service, never its tables
([ADR-0012](docs/architecture/adr/0012-domains-in-one-package-sdks-separate.md)).

**Tenant scoping is not optional.** Every query on a tenant-owned table filters by
`org_id`; every lookup by id checks the row's organisation and answers 404. Add an
integration test that a second organisation cannot see the new data.

**Every action goes through the pipeline.** A new way for an agent to act (a new tool
kind, a new gateway) must call `decisions.pipeline.authorize` and enforce its answer, not
reimplement checks. Steps may only add caution: nothing after a deny may turn it into an
allow, except the one-time redemption of an approval for the same action hash.

**Fail closed.** When a dependency needed to decide is unavailable, deny. Never catch an
error on the decision path and continue as if it allowed.

**Policy semantics are covered by property tests.** Changes to `policies/engine.py` or
`policies/expr.py` keep `test_property_strongest_decision_wins_and_order_does_not_matter`
and `test_property_evaluation_is_a_pure_function` green, and a condition that cannot be
evaluated must never grant.

**The action hash is a contract.** `core/canonical.py`, `sdks/python` and `sdks/node`
compute the same hash. A change to canonicalisation updates
`sdks/testdata/action-hash-vectors.json` (`generate_vectors.py`) and all three
implementations in the same PR.

**Secrets never leave.** No endpoint, log line, audit record, error or exception message
may carry a secret value. New stored credentials are sealed with `container.sealer` and a
context bound to the record. Run the integration suite's log and response scanners.

**Audit every change.** A mutation calls `audit()` in the same session as the change.
Never write to `audit_log` any other way; the database refuses it anyway.

**Work that follows a change is a job in the same transaction.** Use `core.jobs.enqueue`
in the caller's session (with a `dedupe_key` when a retry could enqueue twice), write
results through `JobContext.fenced()`, and keep handlers idempotent. Live events go
through `core.events.emit` so they are published only after commit.

**External systems plug in behind small interfaces.** Secret stores, KMS, storage, mail,
the classifier providers and the sandbox backend each sit behind one module; adding one
means adding a file and a test against the mock services.

**Untrusted code never runs in the API or worker.** Anything that executes code goes
through `agentguard.sandbox.client`.

**Configuration is validated.** A new setting goes in `core/config.py`, is documented in
[docs/guides/configuration.md](docs/guides/configuration.md) in the same PR, and
security-relevant ones are enforced by `guard()` at boot.

**Database changes are new migrations.** Change the models, then autogenerate a revision
with `uv run agentguard revision -m "what changed"` against a local database and review
it. Never edit an applied one. Indexes for every new filter the API exposes belong in the
same revision.

**Comments explain why.** The code says what it does. Comments are for the constraint,
the attack, or the trade-off that made it this way.

**Style.** ruff and mypy `--strict` for Python; ESLint and TypeScript strict for the web
and the Node.js SDK. No em dashes or en dashes anywhere (the sanitization check enforces
it).

## Commit messages

Imperative mood with an optional scope: `policies: break ties by specificity`,
`egress: refuse private addresses allowed by host name`. Explain the why in the body when
it is not obvious.

## Architecture decisions

Significant decisions are recorded in [docs/architecture/adr/](docs/architecture/adr/).
If your change reverses or extends one, add a new ADR rather than editing the old one.
