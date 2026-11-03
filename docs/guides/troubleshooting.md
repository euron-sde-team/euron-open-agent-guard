# Troubleshooting

Every decision carries a `reason_code` and a `reason`. Start there: the decision log
(**Agents > agent > decisions**, or `GET /api/v1/decisions/{id}`) shows the code, every
rule that matched, the risk factors and the evaluation input.

## An action is denied and should not be

| `reason_code` | Cause | Fix |
| --- | --- | --- |
| `no_permission` | No policy rule matched and no permission covers the tool, action and resource | Give one of the agent's roles a permission (Access control), or write a policy `allow`. Check the action name: a permission for `read` does not cover `get` |
| `unknown_tool` | The tool is not registered, and the organisation is in enforce mode (or requires registered tools) | Register it (Tool security). MCP tools appear after discovery, named `<server>.<tool>` |
| `unknown_action` | The tool lists its actions and this is not one of them | Use one of the listed actions, or add it to the tool |
| `invalid_parameters` | The parameters fail the tool's JSON schema or constraints; `reasons` lists every problem | Fix the call; the reasons are written for the model to read |
| `tool_disabled`, `tool_pending_review` | The tool is switched off, or an MCP tool changed upstream and waits for review | Review it in Tool security |
| `policy_deny` | A policy rule denied; `policy` and `policy_version` say which | Read the rule; simulate a change before activating it |
| `approval_required` | Not a denial: the action waits for a person (see below) | Approve it, or change the policy |
| `agent_suspended`, `agent_quarantined` | The agent's status | Read the reason on the agent page; reactivate after investigating |
| `kill_switch` | The organisation's kill switch is on | Settings > Kill switch (org admin) |
| `limit_exceeded` | A usage limit; `reasons` names the limit, the metric and the value | Raise the limit, wait for the window, or end idle runs (`POST /api/v1/runs/{key}/end`) |
| `loop_detected` | The same action (same parameters) more than `loop_threshold` times in five minutes | Fix the agent's loop; raise the threshold only if repetition is legitimate |
| `budget_exhausted` | A watched TokenShield budget is spent, or TokenShield is down with `fail_mode: closed` | Check TokenShield; the detail names the budget |
| `opa_deny`, `opa_unavailable` | OPA decided, or could not be reached for a sensitive tool | Check the Rego and OPA's health (Integrations > OPA > Test) |
| `approval_mismatch` | The agent named an approval given for different parameters | Retry with exactly the approved parameters, or ask again |
| `approval_used`, `approval_rejected`, `changes_requested` | The approval was already used, or a reviewer said no | Read the comment; ask again with changed parameters |
| `guard_unavailable` (HTTP 503) | AgentGuard could not reach Postgres or Redis while deciding, so it denied | `make ps`; check Redis is not full (it runs with `noeviction`). This is fail closed on purpose |

A decision that was allowed but did not run has `execution` set:

| `execution` / `result_meta.error` | Cause | Fix |
| --- | --- | --- |
| `blocked` / `network_blocked` | The tool's host is outside the agent's network policy | Network guard: add a rule, or give the agent the right policy |
| `blocked` / `dns_rebinding` | The connected address was not one that was checked | Usually a host whose DNS changes per lookup; pin it, or report it if unexpected |
| `blocked` / `secret_refused` (`secret_revoked`, `secret_expired`, `secret_no_lease`, `secret_host_not_allowed`) | The secret cannot be used for this call | Rotate or un-revoke, grant a lease, or add the host to `allowed_hosts` |
| `error` / `tool_timeout`, `tool_unreachable`, `response_too_large` | The tool did not answer, could not be reached, or answered too much | Check the tool; raise `timeout_s` or `max_response_bytes` in its config |
| `error` / `mcp_upstream_error` | The MCP server failed; the message is classified ("refused the gateway's credentials (HTTP 401)") | Tool security > the server > Check |
| `error` / `sandbox_unavailable` | The sandbox service did not answer | `make logs SERVICE=sandbox`; check `SANDBOX_TOKEN` matches on both sides |
| `error` / `not_executable` | `execute` was called for a `function` tool | Call `authorize`, run the function yourself, and verify the decision token in it |

## Authentication

| Symptom | Cause | Fix |
| --- | --- | --- |
| `invalid_client` at `/oauth/token` | Wrong id or secret, the credential expired, was rotated out past its grace, was revoked, the address is outside `allowed_cidrs`, or the agent is revoked | Every case gives the same error on purpose. Check the credential's state on the agent page |
| 429 at `/oauth/token` | `TOKEN_RPM` per address | The SDK caches tokens for their lifetime; do not exchange per call |
| `token_revoked` | The credential was revoked, or the agent was revoked (token version bumped) | Exchange new credentials |
| `signature_required`, `bad_signature`, `stale_request`, `replayed_request` | The agent requires signed requests | Pass the signing secret to the SDK; keep the clock in sync (within `REQUEST_SIGNATURE_SKEW_S`); never reuse a nonce |
| `agent_token_required` on a management route, or 401 with an agent token | Agent tokens only reach the agent runtime routes | Use a management API key (`agk_...`) or a session |
| `insufficient_role`, `insufficient_scope` | The person's role or the API key's scope is too low | A read key acts like an auditor, a write key like a security officer |
| 403 on a dashboard change with a valid session | The `X-AgentGuard-CSRF: 1` header is missing (scripts using the cookie) | Send the header, or use an API key |
| Locked out after failed sign-ins | Five failures from one address lock that address for 15 minutes | Wait, or sign in from an address that signed in recently |

## Approvals

| Symptom | Cause | Fix |
| --- | --- | --- |
| "This stage needs ..." | Your role is not one of the stage's roles and you are not named | Ask someone eligible; the request page says who |
| "You cannot approve an action taken on your own behalf" | The run acts for you (`on_behalf_of`) | Another eligible reviewer must approve |
| "Auditors cannot decide approvals" | By design | |
| The approval passed but nothing ran | For `function` tools the agent must retry the same action; for other tools the worker runs it | Check the request's status and result; `make logs SERVICE=worker` |
| An approved request became `failed` | When it ran, the pipeline no longer allowed it (a policy changed, the agent was suspended, the kill switch) | Read the result's reason |
| The agent keeps getting new requests | Its parameters change between attempts (a timestamp, a random id), so every attempt is a new action hash | Keep the parameters stable |
| No approval emails | `notifications.approval_emails` is off, nobody is eligible, or mail is not configured | Mailpit locally (http://localhost:5125); `MAIL_BACKEND` and SES on AWS |

## MCP gateway

| Symptom | Cause | Fix |
| --- | --- | --- |
| 401 from `/mcp` | No or invalid bearer token | Configure the client with the agent's access token in `Authorization` |
| A tool is missing from `tools/list` | No permission or policy could ever allow it for this agent, it is pending review or disabled, or the agent is not active | Grant a permission for `<server>.<tool>` with action `call` |
| "Unknown tool" on `tools/call` | Same as above: hidden tools look like missing ones | As above |
| "Held for approval" | A policy requires approval | Approve it, then retry the exact same call |
| Discovery fails for a stdio server | The command is not on `STDIO_ALLOWED_COMMANDS` | Add the exact command to the operator setting |
| Discovery fails for an HTTP server | The URL is private and `ALLOW_PRIVATE_URLS` is off, or the network policy refuses it | Use a public URL, or a CIDR rule in the default network policy |

## Egress proxy

| Symptom | Cause | Fix |
| --- | --- | --- |
| 407 | Missing or expired agent token in `Proxy-Authorization` | `HTTPS_PROXY=http://<client id>:<token>@egress:3128`, or a Bearer header |
| 403 `Blocked by AgentGuard: not_in_policy` | The policy's default is deny and no rule allows the host | Add a rule |
| 403 `private_address` | The host resolves to a private address and the matching allow is by host name | Allow it with a CIDR rule |
| 403 `metadata_address` | A metadata host or link-local address | Never allowed |
| 403 `agent_not_active`, `kill_switch`, `data_transfer_limit` | The agent's status, the kill switch, or a transfer limit | As for decisions |
| 502 | The destination did not accept the connection within 10 seconds | Check the destination |

## Audit verification

| Problem | Meaning | What to do |
| --- | --- | --- |
| `unsealed` is not zero | Records written in the last seconds are not chained yet | Normal; if it grows, check the worker is running (it seals every 2 s) |
| `missing`, `broken_link`, `record_changed`, `details_changed`, `head_mismatch` | The chain was tampered with, or a database restore mixed states | Treat as an incident; compare with the exported checkpoints |
| `checkpoint_signature` after a key rotation | The checkpoint was signed by a key retired more than a day ago, which the key ring no longer loads | Verify against the retired key's public half you kept; see [security.md](../architecture/security.md#what-agentguard-does-not-guarantee) |
| `checkpoint_mismatch` | The chain at a signed checkpoint differs from what was signed | Treat as an incident |

## The local stack

| Symptom | Cause | Fix |
| --- | --- | --- |
| `make up` fails at `tf-local-floci` | Floci was not ready, or old state | `make down`, then `make up` |
| The sandbox's `/healthz` does not say `nsjail` | User namespaces or the seccomp profile are unavailable on the host | Enable user namespaces (Linux: `kernel.unprivileged_userns_clone=1`); never set `SANDBOX_ALLOW_DEV_FALLBACK` outside development |
| `make demo` prints "seed step ... skipped" | A mock service was not ready | `make down && make up && make demo` |
| A port is in use | Another stack uses the same port | Change the `AG_*_PORT` variable in `deploy/compose/.env` |
| Every decision is `allow` with a different `would_be` | The organisation is in audit mode | Settings > Enforcement > enforce |

More operational failures (alarms, scaling, backups) are in [operations.md](operations.md).
