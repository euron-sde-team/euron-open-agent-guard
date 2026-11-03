# Operations

How to run AgentGuard day to day: health, logs and alarms, backups and restore, secret
rotation, scaling, and what to do when something fails. Commands are given for the local
stack (`make ...`) and for AWS where they differ.

## Health and readiness

| Service | Probe | Notes |
| --- | --- | --- |
| api | `GET /healthz` (liveness), `GET /readyz` (database and cache reachable) | The load balancer uses `/healthz`, so a Redis blip does not pull every task |
| worker | `GET :9464/metrics` | Prometheus metrics; no other HTTP |
| egress | TCP connect to 3128 | A forward proxy has no health path of its own |
| sandbox | `GET /healthz` | Reports `"isolation": "nsjail"`; anything else means the jail is not in use |
| web | `GET /api/healthz` | The Next.js server's own probe |
| postgres, redis, opa, vault, mailpit, floci, mockai | container healthchecks | `make ps` shows each one's state |

Locally, `make ps` lists every container and its health; `make logs SERVICE=api` tails
one service. On AWS, each ECS service has a container healthcheck, a deployment circuit
breaker with rollback, and a "not running" alarm.

## Logs

Every process writes one JSON object per line to stdout: `ts`, `level`, `logger`, `msg`,
the request id when there is one, and structured fields. Values under keys such as
`authorization`, `password`, `secret` and `token` are redacted by the formatter, and
`?token=` in URLs is masked. Secret values never reach a log in the first place.

On AWS each app has its own encrypted log group, `/agentguard/<name_prefix>/<app>` for
api, worker, egress, web, migrate and sandbox. Retention is 14 days in aws-dev and 365
days in aws-prod. WAF logs go to `aws-waf-logs-<name_prefix>` with the authorization,
cookie, API key and CSRF headers and every query string redacted.

## Security metrics and alarms

The `observability` module turns log lines into metrics in the namespace
`AgentGuard/<name_prefix>` and alarms on them through the SNS topic `<name_prefix>-alarms`
(subscribe `alarm_email` or anything else):

| Metric | Matches (CloudWatch filter) | Alarm |
| --- | --- | --- |
| `DecisionsDenied` | `{ $.msg = "decision" && $.decision = "deny" }` (api) | more than 100 in 5 minutes |
| `ThreatsDetected` | `{ $.msg = "threat detected" }` (api, worker) | more than 5 in 5 minutes |
| `AgentsQuarantined` | `{ $.msg = "agent quarantined" }` (api, worker) | any |
| `EgressBlocked` | `{ $.msg = "egress blocked" }` (egress) | more than 50 in 5 minutes |
| `AuditVerifyFailed` | `{ $.msg = "audit verification failed" }` (api: `POST /api/v1/audit-logs/verify`, and the `agentguard verify` CLI) | any |
| `JobFailures` | `{ $.msg = "job failed" }` (worker) | more than 10 in 5 minutes |

Patterns and thresholds are module inputs, so tune them to your agents' normal deny rate.
The module also alarms on 5xx at the load balancer and per service, api p95 latency above
2 seconds, unhealthy targets, a service (or the sandbox) with no running task, CPU and
memory above 85%, database CPU, free storage and connections, and cache memory and CPU.

Cache memory matters more than usual: the cache runs with `noeviction`, so when it is full
writes are refused and AgentGuard denies every action (fail closed) rather than lose
a limit counter or a replay nonce. Scale the node type before the memory alarm stays red.

## Backups and restore

Locally:

```bash
make backup                                 # backups/<timestamp>/: Postgres dump, objects, audit
make restore BACKUP=backups/<timestamp>
```

The dump is taken in one transaction (consistent while the app serves). The restore stops
web, api, worker and egress, replaces the schema with `pg_restore --clean` (the audit log
refuses row updates and deletes, so it is recreated rather than edited), re-uploads the
objects, and starts the services again. Checkpoints already in the Object Lock bucket stay;
the backup's checkpoints are added next to them.

On AWS:

- RDS automated backups (3 days in aws-dev, 14 in aws-prod) and a final snapshot on
  deletion in aws-prod. Restore to a new instance, then update the connections secret
  (`terraform apply` does this when you point the database module at it) and force a new
  deployment.
- The objects bucket is versioned: a replaced or deleted object stays recoverable for 30
  days. Exports expire after 7 days, dumps under `backups/` after `backup_retention_days`.
- The audit bucket is versioned with Object Lock: every checkpoint version is locked for
  `audit_retention_days` from the moment it is written.
- Cross-region replication and S3 access logging are deliberately left to the operator
  (data residency and a log bucket you choose); CloudTrail data events cover object access.

After any restore, run the audit verification (`agentguard verify` in the api container,
or from the dashboard's audit page) to confirm the chain and the checkpoints agree.

## Rotating secrets

| Secret | How | Effect |
| --- | --- | --- |
| `SESSION_SECRET` | put a new value in `<prefix>/app`, force a new deployment | everyone signs in again |
| `TOKEN_PEPPER` | as above | existing API keys, agent client secrets and invitation links stop working: rotate agent credentials first, then the pepper |
| `SANDBOX_TOKEN` | put a new value in `<prefix>/app`, force a new deployment of the sandbox service and then the api and worker | code execution is refused for the minute the two sides disagree |
| Database password | `terraform apply -replace=module.database.random_password.master`, then force a new deployment | the connections secret follows automatically |
| Cache AUTH token | `terraform apply -replace=module.cache.random_password.auth`, then force a new deployment | as above |
| `VAULT_TOKEN` | put new values in `<prefix>/integrations`, force a new deployment | none if the old token stays valid until then |
| KMS key | rotated yearly by AWS (`enable_key_rotation`); old key material keeps decrypting | none |

Terraform ignores later changes to the generated secret values, so a rotation is never
rolled back by the next `terraform apply`. Locally, delete `deploy/compose/.env` and run
`make env` to regenerate every value (then `make down && make up`, since the database's
wrapped keys depend on `LOCAL_MASTER_KEY`).

Agent credentials themselves are rotated in the dashboard or the API: a rotated credential
keeps working for `CREDENTIAL_ROTATION_GRACE_S` (one hour by default), a revoked one stops
immediately.

## Scaling

- api, worker, egress and web scale on CPU (target 60%) between their min and max counts.
  All state lives in Postgres and Redis, so replicas enforce the same limits, kill switch
  and nonces.
- The sandbox scales tasks on CPU, and the ECS capacity provider adds hosts to fit them.
  Each task runs `SANDBOX_CONCURRENCY` programs at once, each up to
  `SANDBOX_MAX_MEMORY_MB`; keep `task_memory` above concurrency times that, plus the
  scratch tmpfs.
- Database connections: `(api_max + worker_max + egress_max + 1) x (DB_POOL_SIZE +
  DB_MAX_OVERFLOW)` must stay under the instance's connection ceiling.

## Kill switch and quarantine

The kill switch (dashboard Settings, or `PUT /api/v1/kill-switch`) denies every action of
an organisation within a second, on every replica: it is stored with the organisation's
settings in Postgres, and each process caches those settings for at most one second. To
stop a single agent, quarantine or suspend it instead; its status is checked on every
decision. A quarantined agent gets `deny` for everything but keeps its credentials, so it
can be released; revoke them from the agent page when it should never come back. The
automatic response to a critical threat does both (quarantine and revoke). All of these are
audited, and none needs a deployment.

## Common failures

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| Every action denied with `guard_unavailable` | Postgres or Redis unreachable, or Redis full (`noeviction`) | Check `make ps` or the cache memory alarm; AgentGuard fails closed on purpose |
| Code execution refused, sandbox healthy | `SANDBOX_TOKEN` differs between the api and the sandbox | Redeploy both after a rotation |
| Sandbox `/healthz` says isolation is not `nsjail` | The host is missing the seccomp profile or user namespaces | Check the sandbox host's `/etc/docker/daemon.json`; never set `SANDBOX_ALLOW_DEV_FALLBACK` outside development |
| Agents get 407 from the egress proxy | Missing or expired agent token on the proxy request | Agents authenticate to the proxy with their own token |
| Agents get 403 from the egress proxy | The destination is outside the agent's network policy | See Network guard in the dashboard; every refusal is recorded |
| Approval email never arrives (AWS) | SES sandbox, or DKIM not published | Request production access; publish `dkim_records` |
| `tf-local-floci` fails in `make up` | Floci not ready, or old state after a manual change | `make down` (deletes the emulator's data and the state together), then `make up` |
| `make down` then `make up` fails on the audit bucket | Never locally: local-floci locks for one day in GOVERNANCE mode and the bucket is destroyed with the emulator volume | If you changed the lock mode locally, restore the default |
