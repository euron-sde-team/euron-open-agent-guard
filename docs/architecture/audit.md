# The audit log

Every decision and every administrative change is an append-only, hash-chained record.
Editing or deleting a row is refused by the database, `verify` detects a tampered, removed
or reordered record, signed checkpoints are exported outside the database, and retention
can drop old details while the chain still verifies
([ADR-0007](adr/0007-hash-chained-audit-single-sealer.md)).

Code: `apps/api/src/agentguard/audit/` (`service.py`, `models.py`, `router.py`), the
triggers in the initial migration
(`migrations/versions/6b884d0193ed_initial_schema.py`), and the sealing, checkpoint and
retention tasks in `background.py`.

## What is recorded

`audit(session, actor, action, target_type, target_id, **details)` is called in the same
transaction as the change it describes, so a change cannot commit without its record.

| Actor type | Who |
| --- | --- |
| `user` | A person in the dashboard (email, role, address) |
| `api_key` | A management API key (`api-key:<name>`) |
| `agent` | An agent (`agent:<slug>`), for its decisions |
| `system` | AgentGuard itself: `limits`, `policy`, `threat-response`, `mcp-discovery`, ... |

Actions include every decision (`decision.allow`, `decision.deny`,
`decision.require_approval`, `decision.restrict`, `decision.quarantine`, with the tool,
action, resource, reason code, policy and version, mode and risk), agent lifecycle
(`agent.registered`, `agent.credential_issued`, `agent.credential_rotated`,
`agent.credential_revoked`, `agent.suspended`, `agent.quarantined`, `agent.reactivated`,
`agent.revoked`), policies (`policy.created`, `policy.version_saved`, `policy.activated`,
`policy.rolled_back`, `policy.disabled`, `policy.deleted`), approvals
(`approval.approve`, `approval.reject`, `approval.request_changes`, `approval.revoked`,
`approval.expired`), secrets (`secret.created`, `secret.rotated`, `secret.revoked`,
`secret.deleted`, `secret.lease_granted`), the kill switch, tools and MCP
(`tool.reviewed`, `mcp.discovered`), integrations, users and settings.

Details are redacted (`redact_value`) before they are stored, and digested:
`details_digest = SHA-256(canonical JSON of the redacted details)`.

## The hash chain

Records are inserted unsealed: `seq`, `prev_hash` and `hash` are null. Writers never wait
for each other.

The worker's `audit.seal` task runs every 2 seconds (and `POST /api/v1/audit-logs/seal`,
`verify` and the CLI seal on demand). For each organisation with unsealed records:

1. `pg_advisory_xact_lock(hashtext('agentguard-audit:<org>'))`: one sealer per
   organisation across every replica.
2. The head row (`audit_heads`: `sealed_seq`, `head_hash`, genesis `0` x 64) is created if
   missing and locked.
3. Up to 2000 unsealed records are read in id order. For each, `seq = previous seq + 1`,
   `prev_hash = previous hash`, and

   ```
   hash = SHA-256( "agentguard-audit-v1\0" || canonical_json([
       prev_hash, seq, at (UTC, microseconds), actor_type, actor_id, actor_name,
       action, target_type, target_id, details_digest ]) )
   ```
4. The head moves to the last record, and the transaction commits.

`seq` is unique per organisation (`uq_audit_log_org_seq`) and gap-free. The chain's order
is the sealer's order, which is insertion order among committed records.

## Database rules

The initial migration installs two trigger functions.

`agentguard_audit_guard` on `audit_log`, `BEFORE UPDATE OR DELETE`:

- `DELETE` is refused.
- `UPDATE` is allowed in exactly two shapes, when every identifying column (`id`,
  `org_id`, `at`, actor, action, target, `details_digest`, `ip`) is unchanged:
  - **sealing**: an unsealed record (`hash IS NULL`) gets `seq` and `hash`, with `details`
    unchanged;
  - **retention**: a sealed record's `details` become null, with `hash`, `seq` and
    `prev_hash` unchanged.
- Everything else raises `audit_log is append-only: UPDATE refused` with SQLSTATE
  `insufficient_privilege`.

`agentguard_refuse_change` on `approval_history`, `audit_checkpoints` and
`secret_access_log` refuses every `UPDATE` and `DELETE`.

Deleting a whole organisation must cascade through these tables, so an operator purge sets
`SET LOCAL agentguard.allow_purge = on` in that transaction; nothing in the application
sets it.

`test_the_audit_chain_verifies_and_refuses_edits` proves the rules;
`test_tampering_is_detected_even_with_database_rules_switched_off` drops the triggers,
edits, deletes and reorders rows, and shows `verify` finds each one.

## Signed checkpoints

Every 300 seconds the `audit.checkpoint` task signs each organisation's head when it moved
since the last checkpoint:

```
message   = "agentguard-audit|<org id>|<seq>|<head hash>|<at, UTC, seconds>"
signature = Ed25519(installation signing key, message), base64url
```

The checkpoint is stored in `audit_checkpoints` (append-only) and exported as JSON to
object storage at `orgs/<org>/audit-checkpoints/<seq, 12 digits>.json` in the audit bucket
(`AUDIT_BUCKET`, else `OBJECTS_BUCKET`). On AWS that bucket has S3 Object Lock, so a
checkpoint cannot be rewritten for `audit_retention_days`. A person who rewrites the whole
chain consistently, triggers and all, still cannot produce the signed head the bucket
holds. `GET /api/v1/audit-logs/checkpoints` lists them.

## Verification

`verify(session, org, keys)` (`POST /api/v1/audit-logs/verify` for the caller's
organisation; `agentguard verify [--org slug]` for every organisation, exit status 1 on any
problem) seals first, then streams the sealed records in `seq` order and checks:

| Problem | Meaning |
| --- | --- |
| `missing` | A gap in `seq` (a record was removed), or a checkpointed record is gone |
| `broken_link` | `prev_hash` is not the previous record's hash (reordered or removed) |
| `details_changed` | The details do not match their digest (edited details) |
| `record_changed` | The record's fields do not hash to its `hash` (edited actor, action, target, time) |
| `head_mismatch` | The chain does not end at the recorded head (truncated) |
| `checkpoint_signature` | A checkpoint's signature does not verify (forged checkpoint) |
| `checkpoint_mismatch` | The chain at a checkpoint's `seq` differs from the signed head (rewritten after the checkpoint) |

It stops collecting after 50 problems, and reports how many records it checked, the head,
the number of still-unsealed records (normal for a few seconds after a write, not a
problem) and the number of checkpoints checked. The dashboard's audit page runs it.

Checkpoint signatures are verified with the signing key named by the checkpoint's `kid`.
The key ring loads keys that are active or were retired less than a day ago, so verify
checkpoints soon after `agentguard rotate-keys`, or keep a copy of the retired public key
for later verification (see [security.md](security.md#what-agentguard-does-not-guarantee)).

## Retention

The hourly `retention` task applies each organisation's `retention` settings:

| Setting | Default | Effect |
| --- | --- | --- |
| `decision_payload_days` | 90 (1 to 3650) | Decision `params` and `context` are emptied; the decision row (outcome, reason, policy version, risk) stays |
| `audit_details_days` | 365 (30 to 3650) | Sealed audit records lose their `details`; the digest stays, so the chain still verifies |
| `egress_days` | 30 (1 to 3650) | Egress events are deleted |

It also deletes decision tokens a day after they expired and request nonces after an
hour. Audit records themselves are never deleted
(`test_signed_checkpoints_and_retention_keep_the_chain_verifiable`).

## Reading and exporting

- `GET /api/v1/audit-logs`: newest first, keyset pagination on id, filters by action
  prefix (`agent.` matches every agent action), actor and target.
- `GET /api/v1/audit-logs/export`: every sealed record as JSON lines, streamed.
- SIEM forwarding (Integrations > SIEM): the `siem.forward` task posts newly sealed
  records in `seq` order, 500 at a time, as `application/x-ndjson` with an optional bearer
  token, and remembers the last `seq` delivered.

All three are available to auditors and above.
