"""The tamper-evident audit trail.

``audit()`` adds a record to the caller's session, so it commits (or rolls back) with the
change it describes: a change without its audit record cannot be committed. Details are
redacted before they are stored.

``seal()`` runs in the worker every few seconds (and on demand): for each organisation,
under an advisory lock, it gives unsealed records their chain position in insertion order
and links them with SHA-256. ``verify()`` walks the chain and the signed checkpoints and
reports the first record that does not match: an edited field, a removed record, a
reordering, a forged checkpoint.
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import orjson
from sqlalchemy import select, text, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from agentguard.audit.models import AuditCheckpoint, AuditHead, AuditLog
from agentguard.core.canonical import canonical_json
from agentguard.core.db import OrgScope
from agentguard.protection.detectors import redact_value

GENESIS = "0" * 64
SEAL_BATCH = 2000


@dataclass(frozen=True, slots=True)
class Actor:
    """Who did something: a person (by role), a management API key, an agent, or the system.
    Always within one organisation."""

    org_id: uuid.UUID
    id: uuid.UUID | None
    email: str | None
    role: str
    ip: str | None = None
    kind: str = "user"

    @property
    def scope(self) -> OrgScope:
        return OrgScope(self.org_id)

    @property
    def label(self) -> str:
        return self.email or self.kind


def system_actor(org_id: uuid.UUID, name: str = "system") -> Actor:
    return Actor(org_id, None, name, "system", kind="system")


def agent_actor(org_id: uuid.UUID, agent_id: uuid.UUID, slug: str, ip: str | None = None) -> Actor:
    return Actor(org_id, agent_id, f"agent:{slug}", "agent", ip, kind="agent")


def _json_safe(value: Any) -> Any:
    return orjson.loads(orjson.dumps(value, default=str))


def details_digest(details: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(details)).hexdigest()


def audit(
    session: AsyncSession,
    actor: Actor,
    action: str,
    target_type: str | None = None,
    target_id: object | None = None,
    /,
    **details: Any,
) -> None:
    safe = redact_value(_json_safe(details))
    session.add(
        AuditLog(
            org_id=actor.org_id,
            actor_type=actor.kind,
            actor_id=str(actor.id) if actor.id else None,
            actor_name=actor.label,
            action=action,
            target_type=target_type,
            target_id=str(target_id) if target_id is not None else None,
            details=safe,
            details_digest=details_digest(safe),
            ip=actor.ip,
        )
    )


def record_hash(
    prev_hash: str,
    seq: int,
    at: datetime,
    actor_type: str,
    actor_id: str | None,
    actor_name: str | None,
    action: str,
    target_type: str | None,
    target_id: str | None,
    digest: str,
) -> str:
    body = canonical_json(
        [
            prev_hash,
            seq,
            at.astimezone(UTC).isoformat(timespec="microseconds"),
            actor_type,
            actor_id,
            actor_name,
            action,
            target_type,
            target_id,
            digest,
        ]
    )
    return hashlib.sha256(b"agentguard-audit-v1\x00" + body).hexdigest()


async def seal(session: AsyncSession, org_id: uuid.UUID) -> int:
    """Seal this organisation's unsealed records. Returns how many were sealed."""
    # One sealer per organisation at a time, across every worker replica.
    await session.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": f"agentguard-audit:{org_id}"}
    )
    await session.execute(
        insert(AuditHead)
        .values(org_id=org_id, sealed_seq=0, head_hash=GENESIS)
        .on_conflict_do_nothing()
    )
    head = await session.scalar(
        select(AuditHead).where(AuditHead.org_id == org_id).with_for_update()
    )
    assert head is not None
    rows = (
        await session.scalars(
            select(AuditLog)
            .where(AuditLog.org_id == org_id, AuditLog.hash.is_(None))
            .order_by(AuditLog.id)
            .limit(SEAL_BATCH)
        )
    ).all()
    seq, prev = head.sealed_seq, head.head_hash
    updates: list[dict[str, Any]] = []
    for row in rows:
        seq += 1
        h = record_hash(
            prev,
            seq,
            row.at,
            row.actor_type,
            row.actor_id,
            row.actor_name,
            row.action,
            row.target_type,
            row.target_id,
            row.details_digest,
        )
        updates.append({"id": row.id, "seq": seq, "prev_hash": prev, "hash": h})
        prev = h
    if updates:
        # One statement for the batch (executemany by primary key), not one round trip per row.
        await session.execute(update(AuditLog), updates)
    head.sealed_seq, head.head_hash = seq, prev
    await session.commit()
    return len(rows)


async def orgs_with_unsealed(session: AsyncSession) -> list[uuid.UUID]:
    rows = await session.scalars(select(AuditLog.org_id).where(AuditLog.hash.is_(None)).distinct())
    return list(rows.all())


@dataclass(slots=True)
class Verification:
    ok: bool
    checked: int
    head_seq: int
    head_hash: str
    unsealed: int
    problems: list[dict[str, Any]] = field(default_factory=list)
    checkpoints_checked: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "checked": self.checked,
            "head_seq": self.head_seq,
            "head_hash": self.head_hash,
            "unsealed": self.unsealed,
            "problems": self.problems,
            "checkpoints_checked": self.checkpoints_checked,
        }


def checkpoint_message(org_id: uuid.UUID, seq: int, head_hash: str, at: datetime) -> bytes:
    return f"agentguard-audit|{org_id}|{seq}|{head_hash}|{at.astimezone(UTC).isoformat()}".encode()


async def verify(session: AsyncSession, org_id: uuid.UUID, keys: Any) -> Verification:
    """Walk the whole chain. ``keys`` is the KeyRing (for checkpoint signatures)."""
    head = await session.get(AuditHead, org_id)
    head_seq = head.sealed_seq if head else 0
    head_hash = head.head_hash if head else GENESIS
    problems: list[dict[str, Any]] = []
    expected_seq, prev = 0, GENESIS
    hashes: dict[int, str] = {}
    checked = 0
    stream = await session.stream_scalars(
        select(AuditLog)
        .where(AuditLog.org_id == org_id, AuditLog.hash.is_not(None))
        .order_by(AuditLog.seq)
        .execution_options(yield_per=1000)
    )
    async for row in stream:
        checked += 1
        expected_seq += 1
        assert row.seq is not None
        assert row.hash is not None
        if row.seq != expected_seq:
            problems.append(
                {"seq": expected_seq, "problem": "missing", "detail": f"next record is #{row.seq}"}
            )
            expected_seq = row.seq
        if row.prev_hash != prev:
            problems.append(
                {"seq": row.seq, "problem": "broken_link", "detail": "previous hash does not match"}
            )
        if row.details is not None and details_digest(row.details) != row.details_digest:
            problems.append(
                {
                    "seq": row.seq,
                    "problem": "details_changed",
                    "detail": "details do not match their digest",
                }
            )
        recomputed = record_hash(
            row.prev_hash or GENESIS,
            row.seq,
            row.at,
            row.actor_type,
            row.actor_id,
            row.actor_name,
            row.action,
            row.target_type,
            row.target_id,
            row.details_digest,
        )
        if recomputed != row.hash:
            problems.append(
                {
                    "seq": row.seq,
                    "problem": "record_changed",
                    "detail": "fields do not match the record hash",
                }
            )
        prev = row.hash
        hashes[row.seq] = row.hash
        if len(problems) >= 50:
            break
    if not problems and (expected_seq != head_seq or prev != head_hash):
        problems.append(
            {
                "seq": head_seq,
                "problem": "head_mismatch",
                "detail": "the chain does not end at the recorded head",
            }
        )
    checkpoints = (
        await session.scalars(
            select(AuditCheckpoint)
            .where(AuditCheckpoint.org_id == org_id)
            .order_by(AuditCheckpoint.seq)
        )
    ).all()
    for cp in checkpoints:
        message = checkpoint_message(org_id, cp.seq, cp.head_hash, cp.at)
        if not await keys.verify_bytes(cp.kid, message, cp.signature):
            problems.append(
                {
                    "seq": cp.seq,
                    "problem": "checkpoint_signature",
                    "detail": f"checkpoint {cp.id} signature invalid",
                }
            )
        elif hashes.get(cp.seq) not in (None, cp.head_hash):
            problems.append(
                {
                    "seq": cp.seq,
                    "problem": "checkpoint_mismatch",
                    "detail": "the chain was rewritten after a signed checkpoint",
                }
            )
        elif cp.seq <= head_seq and cp.seq not in hashes:
            problems.append(
                {"seq": cp.seq, "problem": "missing", "detail": "a checkpointed record is gone"}
            )
    unsealed = await session.scalar(
        select(text("count(*)"))
        .select_from(AuditLog)
        .where(AuditLog.org_id == org_id, AuditLog.hash.is_(None))
    )
    return Verification(
        ok=not problems,
        checked=checked,
        head_seq=head_seq,
        head_hash=head_hash,
        unsealed=int(unsealed or 0),
        problems=problems,
        checkpoints_checked=len(checkpoints),
    )


async def checkpoint(
    session: AsyncSession, org_id: uuid.UUID, keys: Any, storage: Any
) -> AuditCheckpoint | None:
    """Sign the current head (once it moved since the last checkpoint) and export it."""
    head = await session.get(AuditHead, org_id)
    if head is None or head.sealed_seq == 0:
        return None
    last = await session.scalar(
        select(AuditCheckpoint.seq)
        .where(AuditCheckpoint.org_id == org_id)
        .order_by(AuditCheckpoint.seq.desc())
        .limit(1)
    )
    if last is not None and last >= head.sealed_seq:
        return None
    at = datetime.now(UTC).replace(microsecond=0)
    kid, signature = await keys.sign_bytes(
        checkpoint_message(org_id, head.sealed_seq, head.head_hash, at)
    )
    key = f"orgs/{org_id}/audit-checkpoints/{head.sealed_seq:012d}.json"
    body = orjson.dumps(
        {
            "org_id": str(org_id),
            "seq": head.sealed_seq,
            "head_hash": head.head_hash,
            "at": at.isoformat(),
            "kid": kid,
            "signature": signature,
        },
        option=orjson.OPT_INDENT_2,
    )
    await storage.put(key, body, "application/json")
    cp = AuditCheckpoint(
        org_id=org_id,
        seq=head.sealed_seq,
        head_hash=head.head_hash,
        kid=kid,
        signature=signature,
        at=at,
        storage_key=key,
    )
    session.add(cp)
    await session.commit()
    return cp


async def prune_details(session: AsyncSession, org_id: uuid.UUID, before: datetime) -> int:
    """Retention: drop old details, keep the digests (the chain still verifies)."""
    result = await session.execute(
        update(AuditLog)
        .where(
            AuditLog.org_id == org_id,
            AuditLog.at < before,
            AuditLog.details.is_not(None),
            AuditLog.hash.is_not(None),
        )
        .values(details=None)
    )
    await session.commit()
    return int(result.rowcount or 0)  # type: ignore[attr-defined]


async def list_entries(
    session: AsyncSession,
    scope: OrgScope,
    *,
    after_id: int | None,
    limit: int,
    action: str | None = None,
    actor: str | None = None,
    target_id: str | None = None,
) -> list[AuditLog]:
    """Newest first, keyset-paginated on id; ``limit + 1`` rows so the caller can tell
    whether another page exists. ``action`` filters by prefix (``agent.`` matches all)."""
    stmt = (
        select(AuditLog)
        .where(AuditLog.org_id == scope.org_id)
        .order_by(AuditLog.id.desc())
        .limit(limit + 1)
    )
    if after_id is not None:
        stmt = stmt.where(AuditLog.id < after_id)
    if action:
        stmt = stmt.where(AuditLog.action.startswith(action))
    if actor:
        stmt = stmt.where(AuditLog.actor_name.ilike(f"%{actor}%"))
    if target_id:
        stmt = stmt.where(AuditLog.target_id == target_id)
    return list((await session.scalars(stmt)).all())


def entries_digest(rows: Iterable[AuditLog]) -> str:
    h = hashlib.sha256()
    for row in rows:
        h.update((row.hash or "").encode())
    return h.hexdigest()
