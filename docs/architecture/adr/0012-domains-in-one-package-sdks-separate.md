# ADR-0012: Domains are packages inside one API package; SDKs live under `sdks/`

- **Status:** Accepted
- **Date:** 2026-11-02

## Context

The brief describes a `packages/` monorepo (policy engine, identity, secrets, audit and so
on as separate packages). The programme's code conventions package the backend by domain
inside one Python package, with routers, services and models per domain. Splitting into
installable packages would force versioned interfaces between pieces that always ship
together, and the decision pipeline touches almost every domain in one transaction.

The SDKs are different: they are installed into other people's agents and services, in
Python and in Node.js, and must not depend on the server.

## Decision

- `apps/api/src/agentguard/` holds one package per domain (`identity`, `access`, `tools`,
  `policies`, `decisions`, `approvals`, `secrets`, `protection`, `threats`, `risk`,
  `limits`, `network`, `sandbox`, `mcp`, `audit`, `incidents`, `compliance`,
  `integrations`, `org`, `users`, `auth`, `realtime`, `system`), plus `core` for shared
  infrastructure. A domain calls another domain's service, never its tables directly.
- `apps/api/src/agentguard_sandbox/` is the sandbox service, a separate entry point and
  image built from the same source tree. `apps/api/src/mockai/` is the test and demo
  fixture.
- `sdks/python` (`euron-agentguard`) and `sdks/node` (`@euron/agentguard`) are separate
  projects with their own tests, sharing `sdks/testdata/action-hash-vectors.json` with the
  server so the canonical hash is the same in three implementations.

## Consequences

**Good**
- A newcomer finds a feature by its domain name; the decision pipeline is one readable
  module calling domain services.
- The SDKs stay small (an HTTP client and a JWT library) and can be vendored.

**Bad / caveats**
- Domains can still reach into each other's models with an import; the convention, reviews
  and tests are what keep the boundaries.
- Publishing to PyPI and npm is on the roadmap; 0.1.0 installs the SDKs from the repository.

## Alternatives considered

- **The brief's `packages/` split**: clean boundaries on paper, versioning overhead in
  practice, and a pipeline spread over many packages.
- **SDKs inside the API package**: one less directory, but agents would install server
  dependencies.
