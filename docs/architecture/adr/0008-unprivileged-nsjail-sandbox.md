# ADR-0008: Untrusted code runs in an unprivileged nsjail sandbox service

- **Status:** Accepted
- **Date:** 2026-11-02

## Context

Agents run code: a data transformation, a release check, a shell pipeline. That code may
come from a prompt-injected model. It must never run in the API or worker process, which
hold database credentials, the master key and every organisation's secrets. It must not
reach the network unless policy says so, and a hostile program (a fork bomb, a memory
bomb, an infinite loop) must not starve the next run.

Euron Open CodeJudge already runs untrusted programs this way and its hostile suite is
proven.

## Decision

- A separate service (`apps/api/src/agentguard_sandbox`, its own image) on an internal
  network, reached only with `SANDBOX_TOKEN`. The API and the worker post a `RunRequest`
  through `agentguard.sandbox.client`; they never execute submitted code.
- The container is unprivileged: every capability dropped, no new privileges, read-only
  root, Docker's default seccomp plus only the namespace syscalls nsjail needs, bounded
  processes and memory, scratch on tmpfs.
- Each run gets its own nsjail (user, PID, mount, network, IPC and UTS namespaces) with
  rlimits for CPU, memory, processes, file size and output, a wall clock, and a syscall
  filter.
- Network is `none` by default. With policy granting it, the run gets a loopback port
  relayed to the egress proxy, authenticated as the agent with a short-lived proxy token
  the program cannot read.
- The isolation backend is an interface; nsjail is the implementation in 0.1.0.

The details are in [sandbox.md](../sandbox.md).

## Consequences

**Good**
- The hostile suite (`make test-sandbox`) runs in the real image, hardened as in
  production.
- No privileged container and no Docker socket: it runs on ECS on EC2 with a seccomp
  profile and no task role.

**Bad / caveats**
- Not available on Fargate (user namespaces and a custom seccomp profile are needed), so
  AWS runs the sandbox on EC2 capacity.
- nsjail shares the host kernel; a kernel exploit is out of scope. Firecracker and gVisor
  adapters are on the roadmap.

## Alternatives considered

- **Run code in the worker with a subprocess**: one process away from every secret.
- **Docker in Docker or the Docker socket**: the socket is root on the host.
- **Firecracker microVMs**: stronger isolation, heavier operations, and not available in
  most local Docker setups.
