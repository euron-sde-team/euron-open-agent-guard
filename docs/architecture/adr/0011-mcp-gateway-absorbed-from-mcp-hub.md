# ADR-0011: The MCP gateway and catalog are part of AgentGuard

- **Status:** Accepted
- **Date:** 2026-11-02

## Context

MCP is how many agents reach tools. A separate private Euron project, MCP Hub, built an
MCP server catalog and an aggregating gateway. Governing MCP from outside (AgentGuard as a
policy service the hub calls) would mean two products to deploy, two identities per agent,
and two places where a decision could be skipped. On 2026-11-02 it was decided that
AgentGuard absorbs MCP Hub's scope.

MCP has specific risks: tool descriptions are text the model reads (tool poisoning), a
server can change a tool's definition after it was trusted (a rug pull), and outputs come
back into the model's context.

## Decision

- **Catalog** (`mcp/catalog.py`): MCP servers are registered per organisation, over
  streamable HTTP or stdio (stdio only for commands on the operator's
  `STDIO_ALLOWED_COMMANDS` list). Discovery lists every tool, fingerprints each definition
  (SHA-256 over name, title, description, schemas and annotations) and records every
  version in `mcp_tool_versions`. Tools become ordinary entries of the tool registry named
  `<server>.<tool>`. After the first discovery, a new tool or a changed definition goes to
  `pending_review` (every call denied) and raises a `tool_definition_changed` threat; a
  description that fails the injection scan is held at any time.
- **Gateway** (`mcp/gateway.py`): one endpoint, `/mcp`, stateless streamable HTTP with JSON
  responses. An agent authenticates with its AgentGuard token. `tools/list` shows only
  tools the agent could use (`could_allow`); `tools/call` goes through the full decision
  pipeline and trusted execution with source `mcp`.
- **Upstream pool** (`mcp/upstream.py`, adapted from MCP Hub): one long-lived session per
  server, replaced when the server's `config_version` changes, idle connections reaped;
  secrets injected as headers or environment variables at connect time.

## Consequences

**Good**
- MCP calls get the same policies, approvals, limits, taint, output scanning and audit as
  every other action (`test_one_endpoint_lists_only_what_an_agent_may_use`,
  `test_a_changed_tool_definition_is_held_until_reviewed`).
- One identity per agent, one place to revoke it.

**Bad / caveats**
- AgentGuard now carries MCP SDK dependencies and stdio process management.
- `could_allow` is optimistic: a tool allowed only for some arguments is listed, and each
  call is still decided in full.
- MCP resources and prompts are not proxied in 0.1.0; only tools.

## Alternatives considered

- **Keep MCP Hub separate and call AgentGuard per call**: two deployments and a decision
  that could be skipped by talking to the hub directly.
- **Govern MCP only through the egress proxy**: sees hosts, not tools or arguments.
