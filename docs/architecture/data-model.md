# Data model

PostgreSQL 16. One Alembic revision creates the schema, 49 tables and the append-only
triggers: `apps/api/src/agentguard/migrations/versions/6b884d0193ed_initial_schema.py`.
The SQLAlchemy models live in each domain's `models.py`.

Conventions:

- Every tenant-owned table has `org_id uuid NOT NULL REFERENCES orgs ON DELETE CASCADE`
  with an index (the `OrgScoped` mixin). Lookups by primary key check it and answer 404.
- Ids are UUIDv4, except append-heavy tables (`audit_log`, `audit_checkpoints`,
  `approval_history`, `secret_access_log`, `egress_events`, `incident_events`), which use
  `bigint` identities.
- Timestamps are `timestamptz`; `created_at` and `updated_at` come from `TimestampMixin`.
- Flexible documents are JSONB, validated by Pydantic on every write.
- Secret material is never stored in the clear: hashes (peppered HMAC) for things that are
  checked, sealed bytes (KMS or AES-GCM with a record-bound context) for things that are
  used.

## Organisations and people

| Table | Purpose | Key columns | Constraints and indexes |
| --- | --- | --- | --- |
| `orgs` | A tenant | `name`, `slug`, `incident_seq` (per-organisation incident numbers, taken with `UPDATE ... RETURNING`) | unique `slug` |
| `org_settings` | The organisation's security settings, edited as a unit | PK `org_id`; JSONB `enforcement`, `kill_switch`, `threat_responses`, `detection`, `retention`, `notifications`; `ai_api_key_sealed` | One row per organisation ([configuration.md](../guides/configuration.md#organisation-settings)) |
| `projects` | A boundary inside an organisation: agents, tools, resources and secrets belong to one | `name`, `slug`, `description`, `environment` (development, staging, production) | unique `(org_id, slug)` |
| `users` | People of the dashboard | `email`, `name`, `password_hash` (Argon2id, null for SSO-only), `role` (auditor, reviewer, security_officer, org_admin), `is_global_admin`, `disabled`, `oidc_subject`, `last_login_at`, `last_seen_at`, `session_version` | unique index on `lower(email)` across the install: one account per address |
| `invitations` | Pending invitations | `email`, `role`, `token_hash`, `expires_at` (7 days), `accepted_at`, `invited_by` | unique `token_hash` |
| `revoked_sessions` | Signed-out session tokens until they would have expired | PK `jti`, `expires_at` | index on `expires_at` |
| `login_failures` | Failed sign-ins per (account, address) and per account | PK `key` (hash), `failures`, `window_started_at`, `locked_until` | counted with one `INSERT ... ON CONFLICT DO UPDATE` |
| `oidc_providers` | Single sign-on of one organisation | `issuer`, `client_id`, `client_secret_sealed`, `allowed_domains`, `role_claim`, `role_map`, `default_role`, `enabled` | unique `org_id` |
| `api_keys` | Management API keys | `name`, `prefix`, `secret_hash`, `scope` (read, write), `last_used_at`, `revoked_at`, `created_by` | unique `prefix` |

## Agents and identity

| Table | Purpose | Key columns | Constraints and indexes |
| --- | --- | --- | --- |
| `agents` | Agent identities | `project_id`, `slug`, `name`, `description`, `framework`, `owner_user_id`, `labels` (JSONB), `status` (active, suspended, quarantined, revoked), `status_reason`, `status_changed_at`, `token_version`, `require_signed_requests`, `network_policy_id`, `last_seen_at` | unique `(org_id, slug)`; index on `project_id` |
| `agent_credentials` | Client credentials | `agent_id`, `client_id` (`ag_...`), `secret_hash`, `signing_secret_sealed`, `label`, `expires_at`, `grace_until` (rotation), `revoked_at`, `last_used_at`, `allowed_cidrs`, `created_by` | unique `client_id`; `(agent_id, created_at)` |
| `signing_keys` | Installation-wide Ed25519 keys | PK `kid` (sortable by creation), `public_key` (PEM), `private_key_sealed`, `retired_at` | not tenant scoped |
| `request_nonces` | Nonces of signed requests for the signature window | PK `(agent_id, nonce)`, `seen_at` | index on `seen_at`; pruned after the window and hourly |

## Access control

| Table | Purpose | Key columns | Constraints and indexes |
| --- | --- | --- | --- |
| `agent_roles` | Roles for agents | `name`, `description`, `inherits` (names of roles included; cycles refused) | unique `(org_id, name)` |
| `permissions` | What a role grants | `role_id`, `tool` (glob), `actions` (list; empty means any), `resource` (glob, default `*`), `condition` (expression) | index on `role_id` |
| `role_bindings` | Which roles an organisation, a project or an agent holds | `role_id`, `subject_type` (org, project, agent), `subject_id` | unique `(role_id, subject_type, subject_id)`; `(org_id, subject_type, subject_id)` |
| `resources` | Things agents act on whose owner and sensitivity matter | `project_id` (owner), `key` (`<type>:<id>` or a pattern), `name`, `type`, `sensitivity` (public, internal, confidential, restricted), `environment`, `data_classes`, `tags` | unique `(org_id, key)`; index on `project_id` |

## Tools and MCP

| Table | Purpose | Key columns | Constraints and indexes |
| --- | --- | --- | --- |
| `tools` | The tool registry | `project_id`, `name` (`<server>.<tool>` for MCP), `kind` (http, mcp, sandbox, function), `description`, `actions`, `input_schema` (JSON Schema), `constraints`, `resource_template`, `risk`, `sensitive`, `external`, `config` (kind-specific: URL, headers, `secret_headers`, `secret_env`, limits, MCP fingerprint), `status` (active, disabled, pending_review), `mcp_server_id` | unique `(org_id, name)`; indexes on `project_id`, `mcp_server_id` |
| `mcp_servers` | Registered MCP servers | `project_id`, `slug` (namespace), `name`, `transport` (http, stdio), `url`, `command`, `args`, `secret_bindings`, `default_risk`, `config_version`, `enabled`, `health` (unknown, up, degraded, down), `health_detail`, `consecutive_failures`, `latency_ms`, `server_info`, `last_checked_at`, `last_discovered_at` | unique `(org_id, slug)` |
| `mcp_tool_versions` | Every tool definition seen, so a silent change is visible and dated | `server_id`, `tool_name`, `fingerprint`, `definition`, `change` (added, changed, removed), `seen_at`, `reviewed_by`, `reviewed_at` | `(server_id, tool_name, seen_at)` |

## Policies

| Table | Purpose | Key columns | Constraints and indexes |
| --- | --- | --- | --- |
| `policies` | A policy's identity and pointer | `name`, `description`, `status` (draft, active, disabled), `builtin`, `active_version`, `latest_version`, `created_by` | unique `(org_id, name)` |
| `policy_versions` | Immutable versions | `policy_id`, `version`, `source` (YAML as written), `compiled` (JSONB), `comment`, `created_by`, `created_at` | unique `(policy_id, version)` |
| `risk_rules` | Organisation risk rules | `name`, `condition` (expression), `points` (negative lowers), `enabled` | unique `(org_id, name)` |

## Runs and decisions

| Table | Purpose | Key columns | Constraints and indexes |
| --- | --- | --- | --- |
| `runs` | One execution of an agent, named by the agent | `agent_id`, `run_key`, `started_at`, `last_at`, `ended_at`, `tool_calls`, `denied`, `data_bytes`, `tainted_at`, `taint` (source, verdict, score), `on_behalf_of` | unique `(agent_id, run_key)`, upserted atomically; `(agent_id, ended_at, last_at)` for concurrent runs |
| `decisions` | Every decision | `at`, `agent_id`, `run_id`, `source` (api, execute, mcp, preview), `tool`, `action`, `resource`, `action_hash`, `decision` (what enforcement returned), `would_be` (what enforce mode decides), `mode`, `reason_code`, `reasons`, `policy_id`, `policy_name`, `policy_version`, `matched` (every rule that matched), `risk_level`, `risk_score`, `risk_factors`, `data_classes`, `obligations`, `approval_id`, `params` (redacted), `context` (the redacted evaluation input, for simulation), `latency_ms`, `execution` (none, ok, error, blocked, held), `execution_meta`, `on_behalf_of` | `(org_id, at)`, `(agent_id, at)`, `(org_id, decision, at)`, `run_id`; keyset pagination on `(at, id)` |
| `decision_tokens` | Issued decision tokens, for single-use redemption | PK `jti`, `decision_id`, `action_hash`, `expires_at`, `used_at`, `single_use` | index on `expires_at`; pruned a day after expiry |

## Approvals

| Table | Purpose | Key columns | Constraints and indexes |
| --- | --- | --- | --- |
| `approval_requests` | A request to approve one exact action | `decision_id`, `agent_id`, `run_id`, `tool`, `action`, `resource`, `action_hash`, `params_sealed`, `params_preview`, `reason`, `policy_name`, `policy_version`, `risk_level`, `requirement` (stages, expiry, execute, forbid_requester), `current_stage`, `status` (pending, approved, rejected, changes_requested, expired, revoked, executed, failed), `on_behalf_of`, `expires_at`, `decided_at`, `decided_by`, `decision_comment`, `executed_at`, `execution_decision_id`, `result` | `(org_id, status, created_at)`, `(org_id, action_hash)` |
| `approval_votes` | One vote per person per stage | `request_id`, `stage`, `user_id`, `vote` (approve, reject, request_changes), `comment`, `at` | unique `(request_id, stage, user_id)` |
| `approval_history` | Every event of a request | `request_id`, `at`, `event`, `actor`, `details` | **append-only trigger**; index on `request_id` |

## Secrets

| Table | Purpose | Key columns | Constraints and indexes |
| --- | --- | --- | --- |
| `secrets` | Metadata of managed secrets | `project_id`, `name`, `description`, `store` (database, aws, vault, env), `external_ref`, `current_version`, `previous_valid_until`, `expires_at`, `rotation_days`, `rotated_at`, `requires_lease`, `allowed_hosts`, `revoked_at`, `last_used_at`, `hint`, `created_by` | unique `(org_id, name)` |
| `secret_versions` | One row per version | `secret_id`, `version`, `ciphertext` and `wrapped_key` (database store), `external_version` (other stores), `hint`, `created_at`, `created_by` | unique `(secret_id, version)` |
| `secret_leases` | Time-boxed grants of a secret to an agent | `secret_id`, `agent_id`, `expires_at`, `max_uses`, `uses`, `revoked_at`, `reason`, `created_by` | `(secret_id, agent_id)` |
| `secret_access_log` | Every use, refusal, creation and rotation | `secret_id`, `version`, `agent_id`, `decision_id`, `purpose`, `outcome` (used, written, `refused:<reason>`), `detail`, `at` | **append-only trigger**; `(secret_id, at)` |

## Threats, risk and incidents

| Table | Purpose | Key columns | Constraints and indexes |
| --- | --- | --- | --- |
| `threat_events` | Detections | `at`, `agent_id`, `run_id`, `decision_id`, `kind`, `severity`, `detector` (rule, behavioural, ai), `rule`, `summary`, `details`, `occurrences`, `last_seen_at`, `dedupe_key`, `status` (open, acknowledged, resolved, false_positive), `responses`, `incident_id` | `(org_id, at)`, `(agent_id, at)`; partial unique `(org_id, dedupe_key) WHERE status = 'open' AND dedupe_key IS NOT NULL` |
| `agent_baselines` | An agent's normal behaviour | `agent_id`, `computed_at`, `stats` (hours observed, median hourly calls, tools seen) | unique `agent_id` |
| `incidents` | Security incidents | `number` (INC-n), `title`, `severity`, `status` (open, contained, resolved), `summary`, `root_cause`, `resolution`, `agent_ids`, `opened_by`, `assignee_id`, `contained_at`, `resolved_at` | `(org_id, status, created_at)` |
| `incident_events` | The timeline | `incident_id`, `at`, `kind`, `actor`, `text`, `ref_type`, `ref_id` | index on `incident_id` |
| `incident_evidence` | Frozen, hashed snapshots | `incident_id`, `kind`, `ref_id`, `title`, `snapshot`, `sha256`, `added_by`, `added_at` | index on `incident_id` |

Risk assessments are not a table of their own: each decision stores its level, score and
factors, and `GET /api/v1/risk-assessments` reads them.

## Network, sandbox and limits

| Table | Purpose | Key columns | Constraints and indexes |
| --- | --- | --- | --- |
| `network_policies` | Where agents may connect | `name`, `description`, `rules` (ordered), `default_action`, `is_default` | unique `(org_id, name)` |
| `egress_events` | Every recorded outbound connection | `at`, `agent_id`, `run_id`, `source` (proxy, http_tool), `host`, `port`, `ip`, `method`, `decision`, `reason`, `policy_name`, `bytes_up`, `bytes_down`, `duration_ms` | `(org_id, at)`, `(agent_id, at)`; deleted after `retention.egress_days` |
| `sandbox_sessions` | Code runs | `agent_id`, `run_id`, `decision_id`, `tool`, `language`, `network` (none, proxy), `limits`, `code_sha256`, `code_bytes`, `verdict`, `exit_code`, `signal`, `cpu_ms`, `wall_ms`, `memory_kb`, `stdout_bytes`, `stderr_bytes`, `started_at`, `ended_at` | `(org_id, started_at)`; the code itself is not stored |
| `usage_limits` | Limits by scope and metric | `name`, `scope_type` (org, project, agent, user), `scope_id` (null: each subject separately), `metric`, `limit_value`, `window_s`, `on_exceed` (deny, suspend), `enabled` | `(org_id, scope_type, scope_id)`. The counters are in Redis, not in a table |

## Integrations and jobs

| Table | Purpose | Key columns | Constraints and indexes |
| --- | --- | --- | --- |
| `integrations` | TokenShield, OPA or SIEM per organisation | `kind`, `enabled`, `config`, `secret_sealed`, `last_error`, `last_ok_at` | unique `(org_id, kind)` |
| `webhooks` | Outgoing webhooks | `url`, `events`, `secret_sealed`, `active`, `consecutive_failures`, `disabled_reason`, `last_success_at` | |
| `webhook_deliveries` | One row per event per webhook | `webhook_id`, `event`, `payload`, `status` (pending, delivered, failed, dead), `attempts`, `response_status`, `response_ms`, `error`, `created_at`, `delivered_at`, `size` | `(webhook_id, created_at)` |
| `jobs` | The transactional outbox | `org_id` (nullable), `kind`, `payload`, `dedupe_key`, `status`, `attempts`, `max_attempts`, `run_after`, `lease_until`, `worker`, `last_error`, `created_at`, `finished_at` | partial unique `dedupe_key WHERE dedupe_key IS NOT NULL`; `(status, run_after)` for the claim query (`FOR UPDATE SKIP LOCKED`) |

## Audit

| Table | Purpose | Key columns | Constraints and indexes |
| --- | --- | --- | --- |
| `audit_log` | The tamper-evident log | `id`, `seq` (chain position, assigned at sealing), `at`, `actor_type`, `actor_id`, `actor_name`, `action`, `target_type`, `target_id`, `details` (redacted; null after retention), `details_digest`, `ip`, `prev_hash`, `hash` | unique `(org_id, seq)`; `(org_id, at)`; partial `(org_id, id) WHERE hash IS NULL` for the sealer; **trigger allows only sealing and retention** |
| `audit_heads` | The last sealed record per organisation | PK `org_id`, `sealed_seq`, `head_hash` | |
| `audit_checkpoints` | Signed heads | `seq`, `head_hash`, `kid`, `signature`, `at`, `storage_key` | **append-only trigger** |

See [audit.md](audit.md) for the chain and the triggers.

## Names in the plan that map differently

The plan listed some tables by role; in the schema they are: dashboard roles are a column
on `users` (no `user_roles`); sessions are stateless JWTs with `revoked_sessions` (no
`sessions` table); `roles` are `agent_roles`; policies apply through their own `scope`
(no `policy_bindings`); risk assessments are columns of `decisions`; usage counters and
rate limits are Redis keys.
