# Secrets

An agent that holds an API key can do anything that key can, for anyone who steers the
agent. In AgentGuard the credentials of tools live inside AgentGuard and are injected at
execution time into the one call that needs them: an HTTP tool's header, an MCP upstream
connection, a sandbox run's environment. The agent never sees them, and no API, log,
audit record or error returns a value after it was written.

Code: `apps/api/src/agentguard/secrets/` (`service.py`, `models.py`, `router.py`), the
sealer in `core/sealing.py`, the injection points in `decisions/execute.py` and
`mcp/catalog.py`, and the leak check in `decisions/outputs.py`.

## Stores

Each secret chooses where its value lives.

| Store | Value lives in | AgentGuard keeps | Rotation |
| --- | --- | --- | --- |
| `database` (default) | Postgres, encrypted (envelope, below) | Ciphertext and the wrapped data key per version | `POST /secrets/{id}/rotate` writes a new version |
| `aws` | AWS Secrets Manager (Floci locally), at `external_ref` | The Secrets Manager version id per version | AgentGuard writes the new value there and keeps the version id |
| `vault` | HashiCorp Vault KV version 2 (`VAULT_URL`, `VAULT_MOUNT`), at `external_ref` | The Vault version per version | Same pattern |
| `env` | A variable in AgentGuard's own environment, by name | The name, which must be on `ENV_SECRET_ALLOWLIST` | Read-only: rotate where the variable is set |

`aws` is available when `AWS_SECRETS_ENABLED` is true; `vault` when `VAULT_URL` is set
(and must be https in production). Values are limited to 64 KB.

## Envelope encryption

For the `database` store, every version gets its own 256-bit data key:

1. `data_key = random(32)`, `nonce = random(12)`;
2. `ciphertext = nonce || AES-256-GCM(data_key, value, aad = "agentguard-secret|<secret id>|<version>")`;
3. the data key is sealed by the key encryption key: AWS KMS (`KEY_MODE=kms`, `KMS_KEY_ID`)
   with the encryption context `agentguard:record = secret-data-key:<secret id>:<version>`,
   or AES-256-GCM with a key derived from `LOCAL_MASTER_KEY` and the same context as
   associated data (`KEY_MODE=local`).

Because the record's identity is bound as associated data and as encryption context, a
ciphertext or a wrapped key copied to another row does not open. The database alone opens
nothing: an attacker needs both the database and KMS decrypt permission (or the local
master key, which is never in the database).

The same sealer protects other stored credentials, each with its own context: signing
keys, credential signing secrets, approval parameters, OIDC client secrets, webhook and
integration secrets, and the AI classifier key.

## What a secret can be used for

`resolve_for_use()` is the only way a value leaves the module. It is called by:

| Caller | Purpose code | How the value is used |
| --- | --- | --- |
| HTTP tools | `http_tool` | `{secret:name}` placeholders in the tool's `secret_headers` |
| MCP servers | `mcp_upstream`, `mcp_discovery`, `mcp_health` | `secret_bindings`: a header (HTTP) or environment variable (stdio) to `name` or `name|template` with `{value}` |
| Sandbox tools | `sandbox` | `secret_env`: environment variables of the run |

Before returning a value it refuses, and records the refusal in the access log:

| Refusal | When |
| --- | --- |
| `revoked` | The secret was revoked (immediately effective, including the previous version) |
| `expired` | `expires_at` is in the past |
| `host_not_allowed` | `allowed_hosts` is set and the destination host does not match (`api.stripe.com`, `*.corp.example`). A compromised tool configuration cannot send the secret elsewhere |
| `no_lease` | `requires_lease` is on and the agent has no active, unexpired lease with uses left |

## Versions, rotation and grace

Rotating writes version n+1 and keeps version n usable until `previous_valid_until`
(`grace_s`, one hour by default). During the grace period an HTTP tool that gets a 401 with
the new value retries once with the previous one, so the upstream can be switched over
without downtime (`test_rotation_keeps_the_previous_version_during_grace`). Revoking clears
the grace at once.

A secret can carry `rotation_days` (the intended rotation interval, stored with its
metadata) and `expires_at`. The
`secrets.expiring` task sends a `secret.expiring` webhook once a day for secrets that
expire within seven days.

## Leases

A lease is a time-boxed grant of a secret to one agent's executions: 1 minute to 7 days,
optionally at most `max_uses` uses, revocable. With `requires_lease` on, the secret is
injected only into executions of agents holding an active lease, and each use counts
against it (the lease row is locked while it is counted). Leases are how an organisation
hands a temporary credential to an agent for one job.

## The access log

Every use (`used`), every refusal (`refused:<reason>`), every creation and rotation
(`written`) is a row in `secret_access_log` with the secret, version, agent, decision,
purpose and destination host. A trigger refuses changes to it. The secret's page in the
dashboard shows recent use.

## Never returned

- After creation, no endpoint returns a value. The API returns a `hint` (the first three
  and last two characters and the length, or only the length for values of eight
  characters or fewer) so a person can recognise it.
- Decision parameters, audit details and approval previews are redacted by the data
  detectors; credential-named keys (`password`, `api_key`, `token`, `authorization`, ...)
  are always redacted.
- Log lines redact values under credential-named keys, and the SQLAlchemy engine hides
  bound parameters, so a database error never prints a value.
- If a tool echoes a managed secret in its result (a debugging endpoint that returns its
  own API key), the leak check replaces it with `[REDACTED:managed_secret]` before the
  agent sees it and records a `credential_leakage` threat
  (`test_a_tool_echoing_its_credential_is_caught`). This covers the `database` store; the
  values are cached in process memory for 30 seconds for the scan.

`test_secret_values_never_leave_agentguard` and `test_secret_values_never_reach_the_logs`
scan every response and log line of a full flow for the value.

## API

| Endpoint | Who |
| --- | --- |
| `GET /api/v1/secrets`, `GET /api/v1/secrets/{id}` (metadata, versions, leases, recent use) | auditor and above |
| `POST /api/v1/secrets` (write-only value), `PATCH`, `POST .../rotate`, `POST .../revoke`, `DELETE` | security officer and above |
| `POST /api/v1/secrets/{id}/leases`, `DELETE .../leases/{lease_id}` | security officer and above |

Incident containment can revoke a secret (`revoke_secret`), see [threat-detection.md](threat-detection.md#incidents).
