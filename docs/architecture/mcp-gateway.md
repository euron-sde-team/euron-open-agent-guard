# The MCP gateway and catalog

AgentGuard is the single MCP endpoint for an organisation's agents. Agents configure one
URL and their own AgentGuard token; behind it sit every MCP server the organisation
registered, each tool named `<server>.<tool>`, governed by the same policies, approvals,
limits, taint, output scanning and audit as any other action
([ADR-0011](adr/0011-mcp-gateway-absorbed-from-mcp-hub.md)).

Code: `apps/api/src/agentguard/mcp/` (`catalog.py` registration, discovery, review and
health; `upstream.py` the connection pool; `gateway.py` the `/mcp` endpoint) and the MCP
routes in `tools/router.py`.

## The catalog

### Registering a server

`POST /api/v1/mcp/servers` (security officer and above):

| Field | Meaning |
| --- | --- |
| `slug` | The namespace at the gateway (`tickets` gives `tickets.get_ticket`) |
| `transport` | `http` (streamable HTTP) or `stdio` |
| `url` | For `http`. Checked like every outbound URL: http(s), no metadata hosts, public unless `ALLOW_PRIVATE_URLS` (refused in production) |
| `command`, `args` | For `stdio`. The command must be on the operator's `STDIO_ALLOWED_COMMANDS`: registering a stdio server runs a command on the AgentGuard host |
| `secret_bindings` | Header name (http) or environment variable (stdio) to a managed secret name, optionally `name|Bearer {value}` |
| `default_risk` | Risk of the discovered tools; `high` and `critical` also mark them sensitive |
| `project_id` | The project that owns the server and its tools |
| `discover` | Discover the tools right away (default) |

Changing the URL, command, arguments or secret bindings bumps the server's
`config_version` and drops its pooled connection.

### Discovery and fingerprints

Discovery (on registration, on `POST /api/v1/mcp/servers/{id}/discover`, and every 600 s
by the `mcp.discover` task) opens a short-lived session, lists every tool (paginated, at
most 50 pages) and reconciles the tool registry:

- Each tool definition (name, title, description, input schema, output schema,
  annotations) is fingerprinted: SHA-256 over its canonical JSON.
- Every definition seen is recorded in `mcp_tool_versions` with `added`, `changed` or
  `removed`, and when it was seen, so a silent change is visible and dated.
- The title and description are scanned by the prompt injection guard: a tool
  description is text the model reads, so it can carry instructions ("tool poisoning").

| Situation | Result |
| --- | --- |
| First discovery of a server, clean description | Tool added as `active` |
| A new tool on a later discovery | `pending_review` |
| A known tool whose fingerprint changed (a rug pull) | Schema and description updated, `pending_review` |
| A description that fails the injection scan, at any time | `pending_review`, and a `malicious_tool_output` threat |
| A tool the server no longer lists | `disabled` (marked removed); it returns to `pending_review` if it reappears |

A later discovery with added or changed tools records a `tool_definition_changed` threat
for the server and sends a `tool.changed` webhook. A tool in `pending_review` is denied on
every call (`tool_pending_review`) and absent from `tools/list` until a person reviews it
(`test_a_changed_tool_definition_is_held_until_reviewed`).

### Review

`POST /api/v1/tools/{id}/review` with `approve: true` makes the tool `active`; `false`
disables it. The pending rows in `mcp_tool_versions` are stamped with the reviewer and
time, and the review is audited (`tool.reviewed`). `GET /api/v1/tools/{id}/versions`
shows every definition the tool has had.

Discovered MCP tools are ordinary registry entries (`kind: mcp`, action `call`, the
discovered input schema), so permissions, policies, risk, limits and approvals apply by
name. Their input schema is validated before every call.

### Health

The `mcp.health` task (every 60 s) opens a short session to each enabled server: `up`
under 2 s, `degraded` when slower or after one or two failures, `down` after three in a
row. Health and latency are shown in Tool security.

## The gateway: `/mcp`

Stateless streamable HTTP with JSON responses (MCP Python SDK's
`StreamableHTTPSessionManager`). Every request carries the agent's AgentGuard token in
`Authorization: Bearer`; without a valid one the answer is 401 with a JSON-RPC error and
`WWW-Authenticate` (`test_mcp_without_a_valid_token_is_refused`). The optional header
`X-AgentGuard-Run` names the run (the same characters as a `run_id`), so taint and
per-run limits work over MCP.

```json
{
  "mcpServers": {
    "agentguard": {
      "url": "http://localhost:5130/mcp",
      "headers": {
        "Authorization": "Bearer <agent access token>",
        "X-AgentGuard-Run": "ticket-T-1002"
      }
    }
  }
}
```

### `tools/list`: hidden tools

The gateway lists the organisation's `active` MCP tools for which
`engine.could_allow(...)` is true for this agent: a permission covers the tool, or an
applicable policy has an allow, restrict or approval rule naming it or scoped to this
agent. Organisation-wide guards (the built-in policies) do not make a tool visible.
Suspended and quarantined agents see no tools. The check is optimistic (conditions and
resources are ignored), so a tool allowed only for some arguments is listed and each call
is still decided in full (`test_one_endpoint_lists_only_what_an_agent_may_use`).

### `tools/call`: the full pipeline

A call becomes an `AuthorizeRequest` (tool `<server>.<tool>`, action `call`, the
arguments as parameters, the run from the header) and goes through `decisions.execute`
with source `mcp`:

| Outcome | MCP result |
| --- | --- |
| Allowed and executed | The upstream `CallToolResult`, after output processing (obligations, leak check, injection scan, spotlighting) |
| Needs approval | A tool error: "Held for approval (reason). Approval `<id>` expires `<time>`. Retry this exact call after a reviewer approves it." The approval is bound to the exact arguments |
| Denied | A tool error: "Denied by AgentGuard (`<reason_code>`): `<reason>`" |
| Unknown tool | JSON-RPC error `-32602`, like a tool that does not exist, so a hidden tool is indistinguishable from a missing one |
| Allowed but the upstream failed | A tool error with the classified message ("the server refused the gateway's credentials (HTTP 401)") |
| Authentication expired mid-session | A tool error with the message |

MCP tools default to `execute: agentguard` for approvals: once approved, the worker runs
the call itself; the agent can also retry and receives the result through the approval's
status.

### Output scanning

MCP results are untrusted content. With `scan_tool_outputs` on (the default), every text
item is scanned: a result that carries instructions for the model taints the run, records
a `malicious_tool_output` threat and reaches the agent spotlighted (each text item wrapped
in an `<untrusted-data>` boundary with a random id), and managed secret values are
replaced (`test_outputs_are_scanned_and_poisoned_documents_taint_the_run`).

## The upstream pool

`UpstreamPool` keeps one long-lived MCP session per server in a background task (anyio task
groups must be entered and exited by the same task) and multiplexes calls over it:

- a connection is reused while it is usable and its `config_version` is current; otherwise
  a new one is opened with freshly resolved secrets (`connect_timeout_s` 10 s, each call
  bounded by the tool's `timeout_s`, default 60 s, and the pool's 120 s maximum);
- `UpstreamSpec` holds decrypted header and environment values in memory only, and its
  `repr` hides them;
- transport and SDK failures are classified into messages an operator or a model can act
  on;
- discovery and health checks use separate short-lived sessions, so they never disturb
  live traffic.

For HTTP servers, the server URL is checked against the organisation's default network
policy before connecting; secrets bound with `allowed_hosts` are only injected for a
matching host.

The pool has a `reap()` method that closes connections idle for more than 300 s (stopping
idle stdio processes), but in 0.1.0 no task calls it, so connections live until the
server's configuration changes, a connection fails, or the process stops.

## What is not proxied

MCP resources, prompts and sampling are not proxied in 0.1.0; the gateway exposes tools
only.
