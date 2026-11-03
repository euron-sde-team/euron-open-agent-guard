# ADR-0007: Hash-chained audit, sealed by a single writer, guarded by database rules

- **Status:** Accepted
- **Date:** 2026-11-02

## Context

A security product's log is evidence. It must show every decision and every
administrative change, it must not be editable by a bug or by someone holding the
application's database credentials, and an auditor must be able to check that nothing
was edited, removed or reordered. It also sits on the hot path: every decision writes an
audit record, and decisions run in parallel on many replicas.

A naive hash chain needs a per-organisation "previous hash" at insert time, which makes
every writer in an organisation wait for one row lock.

## Decision

- `audit()` adds a record to the caller's session, so it commits or rolls back with the
  change it describes. Details are redacted and hashed separately into `details_digest`.
  Records are inserted **unsealed** (no `seq`, no hashes), so writers never contend.
- The worker's `audit.seal` task (every 2 seconds, and on demand) takes a Postgres
  advisory lock per organisation, reads unsealed records in id order, and gives each a
  gap-free `seq`, its `prev_hash` and its `hash = SHA-256("agentguard-audit-v1\0" ||
  canonical JSON of [prev_hash, seq, at, actor, action, target, details_digest])`. The
  head (`audit_heads`) moves in the same transaction.
- Database triggers (initial migration) refuse every `DELETE` on `audit_log` and every
  `UPDATE` except two shapes: sealing an unsealed row, and retention nulling the details
  of a sealed row while its digest stays. `approval_history`, `secret_access_log` and
  `audit_checkpoints` refuse every change. A whole-organisation purge must set
  `agentguard.allow_purge = on` in its transaction.
- Every 300 seconds the worker signs the head with the installation's Ed25519 key and
  exports the checkpoint as JSON to object storage (S3 Object Lock in Terraform).
- `verify()` (CLI `agentguard verify`, `POST /api/v1/audit-logs/verify`) walks the chain
  and the checkpoints and reports the first problems: a missing record, a broken link,
  changed details, a changed record, a head mismatch, a forged or contradicted checkpoint.

## Consequences

**Good**
- The decision path stays parallel: no counter, no lock, one insert.
- Tampering is detected even with the triggers switched off
  (`test_tampering_is_detected_even_with_database_rules_switched_off`), and rewriting the
  whole chain is caught by the signed checkpoints.
- Retention can drop old details while the chain still verifies
  (`test_signed_checkpoints_and_retention_keep_the_chain_verifiable`).

**Bad / caveats**
- Records are chained a few seconds after commit. Until then they are visible but
  unsealed, and `verify` reports them as `unsealed`, not as problems.
- A database superuser can drop the triggers and rewrite rows; the checkpoints in a
  separate, locked bucket are what catch that.
- The chain order is the sealer's order (insertion id among committed rows), not wall
  clock order.

## Alternatives considered

- **Chain at insert time**: simplest to reason about, but it serialises every decision of
  an organisation on one row.
- **An external ledger (QLDB, a blockchain)**: strong guarantees, one more service, and not
  available locally on Floci.
- **Append-only by convention**: what most applications do; one buggy `UPDATE` ends it.
