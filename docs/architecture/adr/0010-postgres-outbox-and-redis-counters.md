# ADR-0010: Jobs as a Postgres transactional outbox, Redis for counters and pub/sub

- **Status:** Accepted
- **Date:** 2026-11-02

## Context

Many decisions cause follow-up work: an approval request must notify reviewers and expire
on time, an approved action must run, a threat must email the security team, a webhook
must be delivered. Losing that work is a security bug (an approval that never expires, an
alert never sent). Meanwhile limits, loop detection and burst detection need atomic
counters shared by every API replica, and the dashboard needs live updates.

## Decision

- **Jobs** are rows in the `jobs` table inserted in the same transaction as the change that
  needs them, with an optional unique `dedupe_key` (copied from Euron Open SupportDesk).
  `NOTIFY` on commit wakes idle workers; a poll interval covers a missed notification.
  Workers claim with `FOR UPDATE SKIP LOCKED` and a lease (`JOB_LEASE_S`) that a heartbeat
  extends; results go through a fenced session that checks the attempt is still the
  worker's own. Failures retry with backoff (2 s, 10 s, 60 s, 300 s, 1800 s) and the last
  failure marks the job dead.
- **Periodic tasks** (audit sealing, checkpoints, approval expiry, MCP health and
  discovery, behavioural and exfiltration detection, retention, expiring secrets, SIEM
  forwarding) run under a Postgres advisory lock per task, so one replica runs each.
- **Counters** (windowed limits, loop and burst detection, deny streaks, rate limits) are
  atomic Lua scripts in Redis: an add happens only if it stays within the limit. Without
  `REDIS_URL` each process keeps its own counters, exact for one replica.
- **Live events** go over Redis pub/sub, or Postgres `LISTEN/NOTIFY` without Redis; they
  are invalidations, not data.
- Durable security state never lives only in Redis: request nonces and revoked sessions
  are Postgres rows, so eviction cannot bring a replay or a signed-out session back.

## Consequences

**Good**
- A committed approval always has its notification and its expiry job.
- Limits hold exactly under concurrency (`test_limits_hold_exactly_under_concurrency`).
- Redis is optional for a single replica.

**Bad / caveats**
- Polling and claims load Postgres; fine for approval and notification volumes.
- With several replicas and no Redis, counters are per process and limits are per replica.
- When Redis is configured and unreachable, decisions fail closed (`guard_unavailable`):
  a limit that cannot be counted is not skipped.

## Alternatives considered

- **Redis Streams or SQS for jobs**: not atomic with the Postgres write, and Redis would
  become durable state.
- **Counters in Postgres**: atomic and durable, but a row update per request on the hot
  path.
- **Celery**: a broker and a framework, and still not transactional with the business write.
