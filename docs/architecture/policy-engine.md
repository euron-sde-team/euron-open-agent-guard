# The policy engine

Every action an agent asks for is decided by the active policies of its organisation,
then by the agent's permissions, then by the default. The engine is native, deterministic
and explainable ([ADR-0002](adr/0002-native-policy-engine-optional-opa.md)); OPA can be
added on top and can only make a decision stricter.

Code: `apps/api/src/agentguard/policies/` (`dsl.py` the format, `expr.py` the condition
language, `engine.py` the evaluation, `builtin.py` the starting policies, `service.py`
versions and simulation). A practical cookbook is in
[writing-policies.md](../guides/writing-policies.md).

## Decisions

| Decision | Meaning | Strength |
| --- | --- | --- |
| `allow` | The action may run | 0 |
| `restrict` | The action may run with obligations that the execution adapter applies (rows capped, fields redacted, parameters dropped, network off) | 1 |
| `require_approval` | A person must approve this exact action first | 2 |
| `deny` | The action is refused | 3 |
| `quarantine` | The action is refused and the agent is quarantined | 4 |

The strongest decision among every matching rule wins. An explicit deny anywhere beats
every allow, whichever policy it is in, when it was written, or how many allows there are.

## The format

A policy is a YAML document. The brief's example is valid as written:

```yaml
name: production-database-protection
scope:
  agents: [finance-agent, support-agent]
resources: [database:production]
actions: [read, write, delete]
rules:
  read:   {decision: allow}
  write:  {decision: require_approval}
  delete: {decision: deny}
```

For the named agents, `read` on `database:production` is allowed, `write` waits for a
person and `delete` is denied. For every other agent the policy does not apply at all
(`test_brief_policy_allows_reads_holds_writes_denies_deletes`).

### Top-level keys

| Key | Type | Meaning |
| --- | --- | --- |
| `name` | string, required | Lower case, digits, `_ . -`, 2 to 120 characters. Unique in the organisation; it stays the same across versions |
| `description` | string | Shown in the policy list, up to 1000 characters |
| `scope` | mapping | Which agents the policy applies to (below). Empty: every agent |
| `tools` | list of globs | Default tools for rules that name none |
| `resources` | list of globs | Default resources for rules that name none |
| `actions` | list | The actions this policy covers. Rules may not name actions outside it; a rule with no actions gets this list |
| `when` | expression | A condition every rule of the policy also needs |
| `rules` | list or mapping, required | 1 to 200 rules |

Unknown keys anywhere are an error. A policy is limited to 200 KB.

### Scope

| Key | Matches when |
| --- | --- |
| `organization` | The organisation's slug equals it. A policy naming another organisation never applies (`test_a_policy_naming_another_organization_never_applies`) |
| `agents` | The agent's slug matches one of the globs |
| `projects` | The agent's project slug matches one of the globs |
| `roles` | The agent holds at least one of these agent roles |
| `labels` | Every listed label of the agent is equal to the given value |
| `environments` | The agent's project environment (`development`, `staging`, `production`) is listed |
| `frameworks` | The agent's framework (`langgraph`, `crewai`, `mcp`, `python`, `node`, ...) is listed |

Every listed key must match.

### Rules

Rules are a list, or a mapping from an action to a rule (the brief's form; `"*"` as the key
means every action).

| Key | Meaning |
| --- | --- |
| `actions` | Globs over the action. Default: the policy's `actions`, else every action |
| `tools` | Globs over the tool name. Default: the policy's `tools` |
| `resources` | Globs over the resource key. Default: the policy's `resources` |
| `when` | A condition (below) |
| `decision` | `allow`, `deny`, `require_approval`, `restrict` or `quarantine` |
| `reason` | Shown to the agent, the reviewer and the decision log (up to 500 characters). Default: `<policy>: <decision>` |
| `obligations` | Required for `restrict` |
| `approval` | Only for `require_approval`; a default one stage approval when omitted |

Globs follow shell rules (`*`, `?`, `[abc]`) and are case sensitive.

**Quote `"*"` in YAML.** A bare `*` starts a YAML alias, so `actions: [*]` is a YAML error;
write `actions: ["*"]`.

### Approvals

```yaml
approval:
  roles: [reviewer, security_officer]   # one stage: any of these dashboard roles
  users: [cfo@example.com]              # or named people
  count: 2                              # distinct approvals needed (1 to 10)
  expires_in: 8h                        # 1 minute to 30 days: 30m, 8h, 2d or seconds
  execute: auto                         # auto, agentguard or agent
  forbid_requester: true                # the person the run acts for may not approve
```

Ordered stages replace the shorthand:

```yaml
approval:
  stages:
    - {roles: [reviewer], count: 1}
    - {roles: [org_admin], count: 1}
  expires_in: 24h
```

Approver roles are `reviewer`, `security_officer` and `org_admin`; an auditor never
approves. `execute: auto` means AgentGuard runs the action once approved for `http`, `mcp`
and `sandbox` tools, and the agent retries it for `function` tools. See
[approvals.md](approvals.md).

### Obligations

| Obligation | Applied by | Effect |
| --- | --- | --- |
| `max_rows` | output processing | A list result (or its `rows`, `items`, `results`, `data` or `records`) is cut to this many items and marked |
| `redact_fields` | output processing | These keys are replaced with `[REDACTED]` anywhere in the result |
| `redact_output` | output processing | Personal data and credentials found in the result are redacted (with `redact_fields` too) |
| `wrap_untrusted` | output processing | The result is wrapped as untrusted data (spotlighting) |
| `timeout_s` | HTTP and sandbox execution | Caps the tool's timeout or wall clock |
| `max_response_bytes` | HTTP execution | Caps the response size |
| `no_network` | sandbox execution | The run gets no network even if the tool allows the proxy |
| `allow_params` | HTTP and MCP execution | Only these parameters are sent |

When several `restrict` rules match, their obligations are merged most restrictively.
Obligations are returned in the decision and carried in the decision token, so a
`function` tool applies them itself.

## Full examples

**Refunds with stages.** Small refunds pass through permissions, larger ones need one
person, very large ones need two:

```yaml
name: refund-approvals
tools: [payments.refund]
actions: [refund]
rules:
  - when: params.amount > 200 and params.amount <= 1000
    decision: require_approval
    reason: Refunds above 200 EUR are approved by a reviewer
    approval: {roles: [reviewer, security_officer], expires_in: 8h}
  - when: params.amount > 1000
    decision: require_approval
    reason: Refunds above 1000 EUR need a reviewer and then the finance lead
    approval:
      stages:
        - {roles: [reviewer], count: 1}
        - {users: [finance.lead@example.com], count: 1}
      expires_in: 24h
```

**Restrict obligations.** Exports return at most 50 rows with contact details masked:

```yaml
name: customer-export-limits
tools: [crm.export_customers]
rules:
  - actions: [export]
    decision: restrict
    reason: Exports return at most 50 rows with contact details masked
    obligations: {max_rows: 50, redact_fields: [email, phone]}
```

**Time windows.** Deletes only on weekdays during working hours (UTC), and then with a person:

```yaml
name: no-deletes-out-of-hours
tools: [crm.delete_customer]
rules:
  - actions: [delete]
    when: time.hour < 8 or time.hour >= 18 or time.weekday in ["sat", "sun"]
    decision: deny
    reason: Customer records are only deleted during working hours
  - actions: [delete]
    decision: require_approval
    reason: Deleting a customer record needs a person
```

Outside working hours both rules match; deny is stronger and wins.

**Scopes, including `organization`.** A guard for production agents of one organisation:

```yaml
name: production-guard
scope:
  organization: kestrel
  environments: [production]
  labels: {tier: "1"}
rules:
  - actions: ["*"]
    when: resource.sensitivity >= "confidential" and tool.external
    decision: deny
    reason: Tier 1 agents do not send confidential data outside
```

**Quarantine.** An agent that tries to reach credentials stores is stopped, not just denied:

```yaml
name: credential-store-tripwire
rules:
  - actions: ["*"]
    resources: ["vault:*", "secret:*"]
    decision: quarantine
    reason: Agents never read credential stores directly
```

## The expression language

Conditions (`when` in policies, `condition` on permissions and risk rules) are a small,
side-effect-free language, parsed by hand into a tree and evaluated per decision. It is
never passed to `eval`. Sources are limited to 2000 characters and 32 levels of nesting.

### Paths

A path reads the evaluation input. A missing path is `null`.

| Root | Fields |
| --- | --- |
| `agent` | `id`, `slug`, `name`, `project`, `labels.<key>`, `roles`, `framework`, `history.open_threats`, `history.recent_denies` (last ten minutes) |
| `org` | `slug` |
| `project` | `slug`, `environment` |
| `tool` | `name`, `kind` (`http`, `mcp`, `sandbox`, `function`, `unknown`), `risk`, `sensitive`, `external`, `registered`, `actions` |
| `action` | The action string |
| `resource` | `key`, `registered`, `type` (the part before `:` when unregistered), `sensitivity`, `environment`, `data_classes`, `project`, `owned`, `tags.<key>` |
| `params` | The request parameters, nested (`params.customer.country`) |
| `context` | The request's free context plus `data_classes` (found in the parameters: `pii`, `financial`, `credentials`), `pii_count`, `on_behalf_of`, `source` (`api`, `execute`, `mcp`, `preview`), `ip` |
| `run` | `id`, `tainted`, `taint.source`, `taint.verdict`, `taint.score`, `calls`, `age_s` |
| `risk` | `level` (`low`, `medium`, `high`, `critical`), `score` (0 to 100) |
| `time` | `hour` (0 to 23, UTC), `weekday` (`mon` to `sun`), `date` (`YYYY-MM-DD`), `iso` |

Unregistered resources default to sensitivity `internal`, the project's environment and
`owned: true`.

### Values and operators

Values: strings (`'...'` or `"..."`, backslash escapes), integers and decimals, `true`,
`false`, `null`, and lists of literals (`["sat", "sun"]`).

| Operator | Meaning |
| --- | --- |
| `==`, `!=` | Equality |
| `<`, `<=`, `>`, `>=` | Numbers, strings, or ranked levels (below); `null` on either side is false |
| `in`, `not in` | Membership in a list, a substring of a string, a key of a mapping |
| `contains` | The reverse of `in`: `context.data_classes contains "pii"` |
| `startswith`, `endswith` | String prefix and suffix |
| `matches` | The whole value matches a regular expression (a literal pattern of at most 200 characters, checked when the policy is saved; the value is cut at 10 000 characters) |
| `and`, `or`, `not`, `( )` | Logic; `and` binds tighter than `or` |
| a bare path | True when the value is truthy (`tool.external`, `run.tainted`) |

Functions: `len(x)` (length of a string, list or mapping; `null` is 0), `lower(x)`,
`any_of(a, b)` (the two lists share an element).

### Level and sensitivity ordering

Two strings that are both risk levels compare by rank: `low < medium < high < critical`.
Two strings that are both sensitivities compare by rank: `public < internal <
confidential < restricted`. So `risk.level >= "high"` means high or critical, and
`resource.sensitivity >= "confidential"` means confidential or restricted.

### Errors fail closed

A syntax error is refused when the policy is saved, with the position. A condition that
cannot be evaluated against an input (ordering a number against a list, `startswith` on a
number, ordering booleans) raises an evaluation error. The engine then treats the rule as
matching **only if it denies or quarantines**, and records the error on the match: an
error can add caution, never grant (`test_a_broken_condition_can_deny_but_never_grant`).

## Evaluation order

For one action, after the pre-checks of the pipeline ([HLD.md](HLD.md#the-decision-pipeline)):

1. Every active policy, in name order, whose scope matches.
2. Every rule of it whose actions, tools, resources, the policy's `when` and the rule's
   `when` match.
3. The strongest decision among the matches wins. The most specific matching rule of
   that strength explains it (named tools count 4, named resources 3, an agent-targeting
   scope 2, a condition 1, named actions 1), then policy name and rule index.
4. No match: the agent's permissions; the first grant that covers the tool, action and
   resource (and whose condition holds) allows, with reason `permission`.
5. Nothing: the default, `deny` with `no_permission` in enforce mode.
6. OPA, when connected: its decision replaces the result only if it is stronger.
7. Approval handling for `require_approval` (an existing approved request for this exact
   action hash turns it into `allow`, once).

## Permissions and policies

**Permissions grant; policies decide.** A permission (on an agent role) says an agent may
use some actions of some tools on some resources, optionally under a condition. Roles are
bound to the organisation, a project, or one agent, and may inherit other roles. An agent
gets the roles of its organisation, its project and itself.

Policies refine: they hold for approval, restrict, deny or quarantine, and they can also
allow (a policy `allow` stands in for a permission). Because policies are evaluated first
and the strongest wins, a permission can never override a policy's deny, and a policy
allow does not need a permission. When no policy rule matches at all, the permission
decides.

## Built-in policies

Every organisation starts with four policies, marked `builtin`. They are ordinary
policies (visible, versioned, simulatable, editable) that can be tuned or disabled but not
deleted. Because evaluation is deny-overrides, relax one by editing its condition, not by
adding an allow elsewhere.

| Policy | Rule |
| --- | --- |
| `project-boundary` | `resource.registered and resource.project != null and not resource.owned`: deny. A registered resource of another project is off limits |
| `tainted-run-guard` | `run.tainted and risk.level >= "high"`: require approval by a security officer or org admin, 4 h |
| `data-exfiltration-guard` | `tool.external and context.data_classes contains "credentials"`: deny. `tool.external and ("financial" in context.data_classes or context.pii_count >= 3)`: require approval |
| `critical-actions` | `risk.level == "critical"`: require approval |

## Versions

A policy is a name with a history. Every save writes a new immutable version holding the
YAML as written and the compiled form. One version is active, or none (a draft, or a
disabled policy). The policy row is locked while version n+1 is written, so two editors
cannot both create it. The name in the document must stay the same.

| Operation | Endpoint | Audit action |
| --- | --- | --- |
| Create (activated unless `activate: false`) | `POST /api/v1/policies` | `policy.created`, `policy.activated` |
| Save a version | `PUT /api/v1/policies/{id}` | `policy.version_saved` (and `policy.activated`) |
| Activate any version | `POST /api/v1/policies/{id}/activate` | `policy.activated` (with the previous version) |
| Roll back to the version before the active one | `POST /api/v1/policies/{id}/rollback` | `policy.rolled_back` |
| Disable | `POST /api/v1/policies/{id}/disable` | `policy.disabled` |
| Delete (not built-ins) | `DELETE /api/v1/policies/{id}` | `policy.deleted` |

Every change bumps the organisation's policy generation, so the next decision on every
replica reloads the active set. Activation also sends a `policy.activated` webhook. Every
decision records the policy id, name and version that decided it.

## Validation, dry runs and simulation

- **Validate** (`POST /api/v1/policies/validate`): compiles a document and reports the error
  with its location, without saving.
- **Dry run** (`POST /api/v1/policies/evaluate`): "what would happen if this agent did
  this?". Builds the same evaluation input as the pipeline (tool, validation, resource,
  permissions, risk) and evaluates the active policies, optionally with a draft added or
  replacing the policy of the same name. Nothing is recorded or counted: no decision, no
  approval, no limit or loop counters, no threats. The response shows the decision, every
  matched rule, the obligations, the risk factors and the input
  (`test_dry_run_evaluate_explains_without_recording`).
- **Simulation** (`POST /api/v1/policies/simulate`): re-decides recorded decisions of the
  last `days` (default 7, at most 90; up to 20 000 decisions) with a draft, alongside the
  other active policies or in place of the policy being edited, and lists every decision
  whose outcome changes (up to 200) with a summary per transition (`allow->deny: 12`).
  Each decision stored its redacted evaluation input and the grants it was made with, so
  the draft is evaluated against what really happened
  (`test_simulation_reports_exactly_which_decisions_change`).

Simulation has limits worth knowing: decisions made before policies ran (kill switch,
invalid parameters, limits, loops) are skipped; egress connections are not decisions;
parameters are stored redacted, so a condition on a redacted value (an email address, a
card number) sees the redaction marker; permissions are replayed without their conditions;
OPA is not called; and a decision whose recorded outcome came from an approval (`approved`,
`approval_rejected`) is compared with the policy outcome before the approval step, so it
shows as a change from `allow` or `deny` to `require_approval`.

## OPA

An organisation that writes Rego connects OPA in Integrations
(`PUT /api/v1/integrations/opa` with the URL, an optional package and the Rego, which is
pushed to OPA as `agentguard-<org id>`). For every decision that reached policy
evaluation, AgentGuard posts the same evaluation input to
`<url>/v1/data/<package>/decision` with a 2 s timeout. The package defaults to
`agentguard.org_<org id hex>`.

```rego
package agentguard.org_0123abcd

decision := {"decision": "deny", "reason": "No exports on Fridays"} if {
    input.tool.name == "crm.export_customers"
    input.time.weekday == "fri"
}
```

| OPA result | Effect |
| --- | --- |
| no result (`undefined`) | The native decision stands |
| `true` or `{"allow": true}` | The native decision stands (OPA cannot loosen) |
| `false`, `{"allow": false}` | Deny if the native decision was weaker (`opa_deny`) |
| `{"decision": "<d>", "reason": "..."}` | `<d>` if it is stronger than the native decision (`opa_<d>`); `require_approval` gets one stage of security officers or org admins, 24 h |
| an unknown decision or shape | Deny |
| unreachable, non-200, timeout | Sensitive tools are denied (`opa_unavailable`); other tools keep the native decision |

`test_opa_can_add_caution_but_never_grant` proves OPA can add caution and never grant.
