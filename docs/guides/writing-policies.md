# Writing policies

A practical cookbook. The reference (every key, operator and path) is
[policy-engine.md](../architecture/policy-engine.md).

## How to think about it

1. **Permissions grant, policies decide.** Give agents roles with permissions for the tools
   they need; write policies for what needs a person, a restriction or a hard no.
2. **The strongest decision wins.** `quarantine > deny > require_approval > restrict >
   allow`. You never need to order rules; you cannot accidentally shadow a deny with an
   allow.
3. **Default deny.** In enforce mode, anything nothing allows is denied.
4. **Simulate before you activate.** Every save can be simulated against the last seven
   days of real decisions.

## The workflow

```bash
# 1. Validate (nothing saved)
curl -s $AG/api/v1/policies/validate -H "authorization: Bearer $KEY" \
  -H 'content-type: application/json' -d "$(jq -n --rawfile s policy.yaml '{source: $s}')"

# 2. Dry run one action (nothing recorded)
curl -s $AG/api/v1/policies/evaluate -H "authorization: Bearer $KEY" -H 'content-type: application/json' \
  -d "$(jq -n --rawfile s policy.yaml '{agent: "support-agent", draft: $s,
        request: {tool: "payments.refund", action: "refund", parameters: {amount: 450, currency: "EUR"}}}')"

# 3. Simulate against history
curl -s $AG/api/v1/policies/simulate -H "authorization: Bearer $KEY" -H 'content-type: application/json' \
  -d "$(jq -n --rawfile s policy.yaml '{source: $s, days: 7}')"

# 4. Create and activate (or PUT /api/v1/policies/{id} to save a new version)
curl -s $AG/api/v1/policies -H "authorization: Bearer $KEY" -H 'content-type: application/json' \
  -d "$(jq -n --rawfile s policy.yaml '{source: $s, activate: true}')"
```

The dashboard's policy builder does the same with a visual editor, a YAML view, and
Evaluate and Simulate buttons. Check the exact request fields in the API docs
(http://localhost:5130/docs).

## Recipes

### Read freely, write with a person, never delete

```yaml
name: orders-db
scope:
  agents: [support-agent, finance-agent]
resources: ["database:orders"]
actions: [read, write, delete]
rules:
  read:   {decision: allow}
  write:  {decision: require_approval, reason: Writes to orders are checked by a person}
  delete: {decision: deny, reason: Orders are never deleted by an agent}
```

### Amount thresholds and a two-person rule

```yaml
name: payouts
tools: [payments.payout]
actions: [payout]
rules:
  - when: params.amount > 500
    decision: require_approval
    reason: Payouts above 500 need a reviewer
    approval: {roles: [reviewer, security_officer], expires_in: 8h}
  - when: params.amount > 5000
    decision: require_approval
    reason: Payouts above 5000 need two people
    approval: {roles: [security_officer, org_admin], count: 2, expires_in: 24h}
```

Above 5000 both rules match; the approval with more people wins.

### Only certain recipients

```yaml
name: email-recipients
tools: [email.send]
rules:
  - actions: [send]
    when: not (params.to endswith "@kestrel.example")
    decision: require_approval
    reason: Email outside the company needs a person
```

`matches` checks the whole value against a regular expression; in YAML, keep it in single
quotes so backslashes survive: `when: 'params.to matches ".*@(corp|ops)\\.example"'`.

### Cap what an export returns

```yaml
name: export-caps
tools: ["crm.export_*"]
rules:
  - actions: ["*"]
    decision: restrict
    reason: Exports are capped and masked
    obligations: {max_rows: 100, redact_fields: [email, phone, iban]}
```

AgentGuard applies the obligations to HTTP and MCP results; function tools receive them in
the decision (and the decision token) and must apply them themselves.

### Business hours

```yaml
name: business-hours
scope:
  environments: [production]
rules:
  - actions: [delete, deploy, transfer]
    when: time.hour < 8 or time.hour >= 18 or time.weekday in ["sat", "sun"]
    decision: deny
    reason: Destructive actions only during working hours (UTC)
```

Times are UTC.

### Risk-based holds

```yaml
name: high-risk-holds
rules:
  - actions: ["*"]
    when: risk.level >= "high" and resource.environment == "production"
    decision: require_approval
    reason: High-risk actions on production need a person
```

Tune the score with risk rules (Risk center): for example `+20` when
`params.amount > 1000`, or `-10` when `agent.labels.trusted == true`.

### A label that opts an agent out

```yaml
name: pii-handling
rules:
  - actions: ["*"]
    when: context.data_classes contains "pii" and not agent.labels.pii_cleared
    decision: deny
    reason: Only agents cleared for personal data may send it
```

### Stop a tainted run completely

The built-in `tainted-run-guard` holds high-risk actions of a tainted run. To be stricter:

```yaml
name: tainted-runs-read-only
rules:
  - actions: [send, write, delete, transfer, execute]
    when: run.tainted
    decision: deny
    reason: A run that read an injection attempt may only read
```

### Cross-project access for one agent

The built-in `project-boundary` denies registered resources of other projects. Relax it
by editing its condition rather than adding an allow (an allow cannot beat its deny):

```yaml
when: resource.registered and resource.project != null and not resource.owned and not agent.labels.cross_project
```

### A tripwire

```yaml
name: tripwire
rules:
  - actions: ["*"]
    resources: ["secret:*", "vault:*"]
    decision: quarantine
    reason: Agents never touch credential stores directly
```

## Gotchas

- **Quote `"*"`** in YAML lists and keys: `actions: ["*"]`.
- **Globs are case sensitive** and match the whole string (`crm.*` matches `crm.get` but
  not `xcrm.get`).
- **A missing path is `null`**, and ordering with `null` is false: `params.amount > 500` is
  false when there is no amount. Use `params.amount == null` to catch absent values.
- **Type errors deny only.** `params.amount > 500` with a string amount is an evaluation
  error: a deny rule with that condition matches, an allow rule does not. Validate types
  with the tool's input schema instead.
- **Actions outside the policy's `actions`** are an error in rules; leave `actions` out of
  the policy if rules should name their own.
- **Names are permanent.** Saving a version with a different `name` is refused; create a
  new policy instead.
- **Audit mode allows everything.** Use it to roll out, then switch to enforce.
- **Simulation is approximate where data is redacted.** Conditions on values the detectors
  redact (emails, card numbers) see the redaction marker in recorded decisions.
