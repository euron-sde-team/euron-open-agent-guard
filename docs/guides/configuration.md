# Configuration

Two layers:

- **Deployment settings** come from the environment, are read once at boot by `Settings`
  in `apps/api/src/agentguard/core/config.py` (the API, the worker, the egress proxy and
  the CLI all use it), and are checked by `guard()` when `ENVIRONMENT=production`. Names
  are case insensitive.
- **Organisation settings** (enforcement mode, kill switch, detection, threat responses,
  retention, notifications) live in the database and are edited in Settings by org
  admins. They take effect within a second on every replica; nothing restarts.

Locally, `deploy/compose/compose.yaml` sets the deployment settings and `make env` writes
the secrets to `deploy/compose/.env` (documented in `deploy/compose/.env.example`). On AWS
the Terraform `service` module sets them, with secrets from Secrets Manager.

## Environment variables (API, worker, egress, CLI)

### Runtime

| Variable | Default | Meaning |
| --- | --- | --- |
| `ENVIRONMENT` | `development` | `development`, `test` or `production`. Production runs the boot guards |
| `LOG_LEVEL` | `INFO` | Level of the JSON logs |
| `AGENTGUARD_CLOUD` | `local` | `local`, `floci` or `aws`. With `aws`, `AWS_ENDPOINT_URL` must be unset in production |
| `OTEL_ENABLED` | `false` | OpenTelemetry tracing hooks |

### Database and cache

| Variable | Default | Meaning |
| --- | --- | --- |
| `DATABASE_URL` | `postgresql+asyncpg://agentguard:agentguard@localhost:5142/agentguard` | Postgres 16 |
| `DB_POOL_SIZE` | `10` | SQLAlchemy pool per process |
| `DB_MAX_OVERFLOW` | `20` | Extra connections above the pool |
| `REDIS_URL` | empty | Counters, rate limits, the policy generation and live events shared by every replica. Empty: each process keeps its own (exact for one replica). When set and unreachable, decisions fail closed |
| `MEMORY_CACHE_MAX_BYTES` | `64000000` | Byte budget of the in-process KV store when `REDIS_URL` is empty (minimum 1,000,000) |

### Sessions, tokens and URLs

| Variable | Default | Meaning |
| --- | --- | --- |
| `SESSION_SECRET` | dev placeholder | Signs dashboard sessions. Production: random, at least 32 characters |
| `TOKEN_PEPPER` | dev placeholder | Peppers the hashes of API keys, agent client secrets, invitation tokens and lockout keys. Production: random, at least 32 characters, different from the others. Changing it invalidates existing client secrets and API keys |
| `SESSION_TTL_HOURS` | `12` | Dashboard session lifetime |
| `COOKIE_SECURE` | `false` | `Secure` flag on the session cookie. Must be true in production |
| `CORS_ORIGINS` | `http://localhost:5110` | Comma-separated dashboard origins. `*` is refused in production |
| `PUBLIC_URL` | `http://localhost:5110` | Where people open the dashboard (links in approval and threat emails). https in production |
| `PUBLIC_API_URL` | `http://localhost:5130` | Where agents and SDKs reach the API; also the `iss` of agent, decision and proxy tokens. https in production |
| `SIGNUP_ENABLED` | `true` | Anyone may create an organisation from the sign-up page. Turn off on a private install once your organisation exists |
| `FORWARDED_ALLOW_IPS` | `127.0.0.1` | Addresses allowed to set `X-Forwarded-For` (read by `agentguard serve`; the load balancer's network on AWS) |

### Agent tokens and requests

| Variable | Default | Meaning |
| --- | --- | --- |
| `AGENT_TOKEN_TTL_S` | `900` | Lifetime of agent access tokens (60 to 86 400) |
| `DECISION_TOKEN_TTL_S` | `60` | Lifetime of decision tokens (5 to 3600) |
| `REQUEST_SIGNATURE_SKEW_S` | `300` | Signed requests must arrive within this window of their timestamp (10 to 3600) |
| `CREDENTIAL_ROTATION_GRACE_S` | `3600` | How long a rotated agent credential keeps working (0 to 7 days) |

### Keys, storage and secret stores

| Variable | Default | Meaning |
| --- | --- | --- |
| `KEY_MODE` | `local` | `local` (AES-GCM with a key derived from `LOCAL_MASTER_KEY`) or `kms` (AWS KMS). Wraps secret data keys and seals every stored credential |
| `LOCAL_MASTER_KEY` | dev placeholder | The local key file's value. Keep it outside the database; required in production with `KEY_MODE=local` |
| `KMS_KEY_ID` | `alias/agentguard-local` | The KMS key with `KEY_MODE=kms` |
| `AWS_REGION` | `us-east-1` | Region for KMS, S3, Secrets Manager and SES |
| `AWS_ENDPOINT_URL` | unset | Floci locally; unset on AWS |
| `S3_FORCE_PATH_STYLE` | `false` | Path-style S3 addressing (Floci) |
| `STORAGE` | `local` | `local` (a directory) or `s3` for evidence, exports and checkpoints |
| `LOCAL_STORAGE_DIR` | `./.data/objects` | The directory with `STORAGE=local` |
| `OBJECTS_BUCKET` | `agentguard-local-objects` | Evidence, incident exports, compliance exports |
| `AUDIT_BUCKET` | empty | Signed audit checkpoints (S3 Object Lock in Terraform). Empty uses `OBJECTS_BUCKET` |
| `VAULT_URL` | empty | HashiCorp Vault for secrets of store `vault`. https in production |
| `VAULT_TOKEN` | empty | Vault token |
| `VAULT_MOUNT` | `secret` | The KV version 2 mount |
| `AWS_SECRETS_ENABLED` | `true` | Allow secrets of store `aws` (AWS Secrets Manager) |
| `ENV_SECRET_ALLOWLIST` | empty | Comma-separated host environment variables a secret of store `env` may reference |

### Mail

| Variable | Default | Meaning |
| --- | --- | --- |
| `MAIL_BACKEND` | `log` | `log` (kept in memory: development, tests), `smtp` (Mailpit locally, any relay) or `ses`. `log` is refused in production, because approval requests go by email |
| `MAIL_FROM_NAME` | `AgentGuard` | Sender name |
| `MAIL_FROM_ADDRESS` | `agentguard@agentguard.local` | Sender address |
| `SMTP_HOST` | `localhost` | SMTP relay |
| `SMTP_PORT` | `5126` | SMTP port (1 to 65535) |

### Sandbox and egress

| Variable | Default | Meaning |
| --- | --- | --- |
| `SANDBOX_URL` | `http://localhost:5135` | The sandbox service |
| `SANDBOX_TOKEN` | dev placeholder | Shared with the sandbox service; every run carries it. Production: random, at least 32 characters |
| `SANDBOX_TIMEOUT_S` | `60` | Client timeout for one run (up to 900) |
| `EGRESS_URL` | `http://localhost:5128` | The egress proxy, given to sandbox runs with network |
| `EGRESS_LISTEN_PORT` | `5128` | Port the egress proxy listens on (`agentguard egress`; 3128 in Compose and on AWS) |
| `EGRESS_MAX_TUNNEL_S` | `600` | Longest connection the proxy relays (5 to 86 400) |

The sandbox service's own variables (`SANDBOX_CONCURRENCY`, `SANDBOX_MAX_MEMORY_MB`,
`SANDBOX_MAX_PIDS`, `SANDBOX_MAX_FILE_MB`, `SANDBOX_ALLOW_DEV_FALLBACK`, ...) are in
[sandbox.md](../architecture/sandbox.md).

### Integrations and outbound requests

| Variable | Default | Meaning |
| --- | --- | --- |
| `OPA_URL` | empty | Default OPA address for organisations that connect OPA without a URL of their own |
| `TOKENSHIELD_URL` | empty | Default TokenShield address |
| `AI_ALLOW_PRIVATE_ENDPOINTS` | `true` | Classifier endpoints may be private addresses (Ollama in the same network). In production only together with `SIGNUP_ENABLED=false` |
| `AI_TIMEOUT_S` | `20` | Classifier timeout |
| `STDIO_ALLOWED_COMMANDS` | empty | Comma-separated commands a stdio MCP server may run on this host |
| `ALLOW_PRIVATE_URLS` | `false` | Tool endpoints, MCP servers, webhooks and integrations may be private addresses (demos). Metadata addresses stay refused. Refused in production |

### Limits and processes

| Variable | Default | Meaning |
| --- | --- | --- |
| `MAX_BODY_BYTES` | `1000000` | Request bodies above this are refused before parsing (minimum 10 000) |
| `MAX_TOOL_RESPONSE_BYTES` | `5000000` | Largest tool response AgentGuard relays or scans (minimum 10 000) |
| `LOGIN_RPM` | `20` | Sign-in attempts per minute per address |
| `SIGNUP_RPM` | `5` | Sign-ups per minute per address |
| `TOKEN_RPM` | `120` | Token exchanges per minute per address |
| `HTTP_KEEP_ALIVE_S` | `75` | Idle keep-alive of the API; keep it above the load balancer's idle timeout (Terraform sets 310) |
| `WORKER_POLL_INTERVAL_S` | `5` | How often an idle worker polls for jobs (NOTIFY wakes it sooner) |
| `WORKER_CONCURRENCY` | `8` | Jobs one worker runs at once (1 to 64) |
| `JOB_LEASE_S` | `120` | A job's lease; a dead worker's jobs are reclaimed after it |
| `WORKER_METRICS_PORT` | `9464` | Prometheus metrics of the worker (0 turns it off) |

## Organisation settings

Edited in **Settings** (org admin), `GET` and `PATCH /api/v1/settings`. Each document is
validated with unknown keys refused.

### Enforcement

| Setting | Default | Meaning |
| --- | --- | --- |
| `mode` | `enforce` | `enforce` decides; `audit` allows everything and records `would_be`, to roll AgentGuard out safely |
| `default_decision` | `deny` | When no policy and no permission decides. `allow` is honoured only in audit mode |
| `require_registered_tools` | `true` | Unregistered tools are denied (`unknown_tool`). Off (audit mode only) records them as `unknown` instead |
| `always_issue_tokens` | `false` | Mint a decision token with every allow, not only for function tools |
| `loop_threshold` | `6` | Identical actions in five minutes before the loop guard denies (2 to 1000) |
| `burst_per_minute` | `120` | Calls of one tool by one agent per minute before a tool-abuse threat |
| `deny_streak` | `8` | Denials in ten minutes before a privilege-escalation threat |
| `run_idle_s` | `600` | Runs idle this long no longer count as concurrent |

### Kill switch

`POST /api/v1/kill-switch` with `active` and a `reason` (required to switch on). While on,
every action of the organisation is denied (`kill_switch`) and the egress proxy refuses
its agents. It applies within a second on every replica and is audited. To stop one agent,
suspend or quarantine it.

### Detection

| Setting | Default | Meaning |
| --- | --- | --- |
| `scan_tool_outputs` | `true` | Scan results AgentGuard relays for injection and managed secrets |
| `taint_on` | `injection` | Taint a run on `injection` only, or on `suspicious` too |
| `ai_provider` | `none` | `none`, `openai` (any OpenAI-compatible endpoint), `ollama`, `anthropic` |
| `ai_base_url`, `ai_model` | empty | The classifier endpoint and model. The key (`ai_api_key`) is write-only and sealed |
| `anomaly_z` | `6.0` | Robust z-score of hourly volume for a behavioural anomaly (2 to 50) |

### Threat responses

Per severity, a list of `quarantine`, `revoke_credentials`, `incident`, `notify`.
Defaults: low none; medium `notify`; high `incident`, `notify`; critical `quarantine`,
`revoke_credentials`, `incident`, `notify`.

### Retention

| Setting | Default | Range |
| --- | --- | --- |
| `decision_payload_days` | 90 | 1 to 3650: decision parameters and evaluation input are emptied after it |
| `audit_details_days` | 365 | 30 to 3650: audit details are dropped after it; the chain still verifies |
| `egress_days` | 30 | 1 to 3650: egress events are deleted after it |

### Notifications

| Setting | Default | Meaning |
| --- | --- | --- |
| `approval_emails` | `true` | Email eligible reviewers about new approval requests |
| `threat_email_min_severity` | `high` | Lowest severity emailed to security officers and org admins (`off` for none) |
| `extra_recipients` | empty | Up to 20 more addresses for threat emails |

Other per-organisation configuration lives on its own pages: projects, agents and
credentials, roles and permissions, resources, tools and MCP servers, policies, risk
rules, secrets, network policies, limits, webhooks, API keys, integrations (OPA,
TokenShield, SIEM) and OIDC.

## Ports

All host ports are bound to 127.0.0.1 and can be changed in `deploy/compose/.env`:

| Service | Variable | Default |
| --- | --- | --- |
| web | `AG_WEB_PORT` | 5110 |
| Mailpit UI | `AG_MAILPIT_PORT` | 5125 |
| Mailpit SMTP | `AG_SMTP_PORT` | 5126 |
| egress | `AG_EGRESS_PORT` | 5128 |
| api | `AG_API_PORT` | 5130 |
| sandbox (through `sandbox-gateway`) | `AG_SANDBOX_PORT` | 5135 |
| postgres | `AG_PG_PORT` | 5142 |
| mockai | `AG_MOCK_AI_PORT` | 5150 |
| floci | `AG_FLOCI_PORT` | 5166 |
| redis | `AG_REDIS_PORT` | 5179 |
| opa | `AG_OPA_PORT` | 5181 |
| vault | `AG_VAULT_PORT` | 5182 |

Other optional values in `deploy/compose/.env`: `AG_LOG_LEVEL`, `AG_MAIL_BACKEND` (ses or
smtp under the Floci overlay), `AG_ENV_SECRET_ALLOWLIST`, `AG_STDIO_ALLOWED_COMMANDS`,
`AG_TOKENSHIELD_URL`, `AG_DEMO_PASSWORD`.
