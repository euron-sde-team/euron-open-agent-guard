# Quickstart (local)

Everything runs in Docker on one machine. No AWS account, no API keys, no other Euron
product.

## Prerequisites

- Docker with Compose v2 (Docker Desktop, or Docker Engine on Linux with user namespaces
  enabled, which the sandbox needs)
- `make`, `bash`, `openssl`, `curl`
- Python 3.10 or later with [uv](https://docs.astral.sh/uv/) or pip, for the SDK example
- About 4 GB of disk for the images
- Free local ports 5110, 5125, 5126, 5128, 5130, 5135, 5142, 5150, 5166, 5179, 5181, 5182
  (change any of them in `deploy/compose/.env`, see [configuration.md](configuration.md#ports))

## Start

```bash
git clone https://github.com/euron-sde-team/euron-open-agent-guard.git
cd euron-open-agent-guard
make up      # Postgres, Redis, Floci (provisioned by Terraform), OPA, Vault, Mailpit, mock services, api, worker, egress, sandbox, web
make demo    # Kestrel Labs: five agents, tools over HTTP, MCP and the sandbox, policies, secrets, 30 days of history
```

`make up` runs `make env` first, which writes `deploy/compose/.env` with random local-only
secrets (once; delete the file to regenerate). It then builds the images, applies the
`local-floci` Terraform against the emulator (KMS key, buckets, Secrets Manager entries,
SES identity), runs the migrations and waits until every service is healthy.

When it is up:

| What | URL |
| --- | --- |
| Dashboard | http://localhost:5110 |
| API docs (OpenAPI) | http://localhost:5130/docs |
| Egress proxy | http://localhost:5128 |
| Mailpit: every email the stack sends (approval requests, threat alerts) | http://localhost:5125 |
| Mock services (classifier, OIDC, TokenShield, demo tools, demo MCP servers) | http://localhost:5150 |

## Sign in

`make demo` prints the logins. Every demo account uses the password `Demo-Pass-2026`.

| Who | Email | Role |
| --- | --- | --- |
| Nora Lindqvist | `nora@kestrel.example` | org admin |
| Omar Haddad | `omar@kestrel.example` | security officer (owns the agents) |
| Priya Raman | `priya@kestrel.example` | reviewer |
| Daniel Okafor | `daniel@kestrel.example` | reviewer |
| Elena Rossi | `elena@kestrel.example` | auditor |

The demo agents are `support-agent`, `finance-agent` (it must sign its requests),
`research-agent`, `coding-agent` and `ops-agent` (quarantined this morning).
[walkthrough.md](walkthrough.md) tours what the seed set up.

## Your first agent in five minutes

The steps below register an agent, give it permission for one tool, and take a decision
through the Python SDK. Sign in as Nora (org admin) for step 1.

### 1. A management API key

In the dashboard: **Integrations > API keys > New key**, scope `write`. Copy the key
(`agk_...`, shown once).

```bash
export AG=http://localhost:5130
export KEY=agk_...   # the key you just created
```

### 2. A tool, a role and an agent

A `function` tool runs in your own process; AgentGuard decides and hands back a decision
token.

```bash
curl -s $AG/api/v1/tools/register -H "authorization: Bearer $KEY" -H 'content-type: application/json' -d '{
  "name": "greeter", "kind": "function", "actions": ["greet"], "risk": "low",
  "input_schema": {"type": "object", "properties": {"name": {"type": "string", "maxLength": 40}},
                   "required": ["name"], "additionalProperties": false}
}'

curl -s $AG/api/v1/roles -H "authorization: Bearer $KEY" -H 'content-type: application/json' -d '{
  "name": "greeters", "permissions": [{"tool": "greeter", "actions": ["greet"]}]
}'

curl -s $AG/api/v1/agents/register -H "authorization: Bearer $KEY" -H 'content-type: application/json' -d '{
  "slug": "hello-agent", "name": "My first agent", "framework": "python", "roles": ["greeters"]
}'
```

The last response contains `credential.client_id` (`ag_...`) and
`credential.client_secret` (`ags_...`). They are shown once; keep them out of your
repository.

### 3. Install the SDK

The SDK is installed from the repository in 0.1.0:

```bash
uv pip install ./sdks/python        # or: pip install ./sdks/python
```

### 4. Decide

```python
from euron_agentguard import AgentGuard

guard = AgentGuard("http://localhost:5130", "ag_...", "ags_...")

ok = guard.authorize("greeter", "greet", parameters={"name": "Ada"}, run_id="first-run")
print(ok.decision, ok.reason_code, ok.reason)       # allow permission Granted by role greeters

bad = guard.authorize("greeter", "delete", parameters={"name": "Ada"}, run_id="first-run")
print(bad.decision, bad.reason_code)                 # deny unknown_action

odd = guard.authorize("greeter", "greet", parameters={"name": 42}, run_id="first-run")
print(odd.decision, odd.reason_code)                 # deny invalid_parameters
```

The SDK exchanged the credentials at `/oauth/token` for a 15-minute token and refreshes it
by itself. Open **Agents > hello-agent** in the dashboard: the three decisions are there
with their reasons, and **Audit logs** shows them chained.

To make the tool itself enforce the decision, ask for a decision token and verify it where
the tool runs:

```python
from euron_agentguard import DecisionVerifier

d = guard.authorize("greeter", "greet", parameters={"name": "Ada"}, want_token=True)
verifier = DecisionVerifier("http://localhost:5130", "agk_...")   # a key of the same organisation
verifier.verify(d.decision_token, tool="greeter", action="greet", parameters={"name": "Ada"})
# a second verify of the same token, or one with other parameters, raises DecisionRejected
```

Next steps: run the same agent through a policy (Policies > New policy, simulate it,
activate it, decide again), or try an HTTP tool through `guard.execute(...)` so AgentGuard
injects the credential itself. [writing-policies.md](writing-policies.md) has recipes.

## Stop

```bash
make down    # stops the stack and deletes its data
```

`make down` deletes the database, Redis, the object store and the emulator's state.
`make up && make demo` starts over.
