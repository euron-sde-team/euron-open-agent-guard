"""The audit log: search, verify the chain, checkpoints, export."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from datetime import datetime
from typing import Any

import orjson
from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select

from agentguard.audit import service
from agentguard.audit.models import AuditCheckpoint, AuditLog
from agentguard.auth.dependencies import StaffRead, StaffWrite
from agentguard.core.deps import ContainerDep, SessionDep
from agentguard.core.schemas import Page, decode_cursor, encode_cursor

log = logging.getLogger("agentguard.audit")

router = APIRouter(prefix="/api/v1/audit-logs", tags=["audit"])


class AuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    seq: int | None
    at: datetime
    actor_type: str
    actor_id: str | None
    actor_name: str | None
    action: str
    target_type: str | None
    target_id: str | None
    details: dict[str, Any] | None
    ip: str | None
    hash: str | None
    prev_hash: str | None


class CheckpointOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    seq: int
    head_hash: str
    kid: str
    signature: str
    at: datetime
    storage_key: str | None


class VerifyOut(BaseModel):
    ok: bool
    checked: int
    head_seq: int
    head_hash: str
    unsealed: int
    problems: list[dict[str, Any]]
    checkpoints_checked: int


@router.get("", response_model=Page[AuditOut], summary="Audit records, newest first")
async def list_entries(
    actor: StaffRead,
    session: SessionDep,
    action: str | None = Query(
        None, max_length=64, description="Prefix: agent. matches every agent action"
    ),
    actor_name: str | None = Query(None, alias="actor", max_length=100),
    target_id: str | None = Query(None, max_length=64),
    cursor: str | None = None,
    limit: int = Query(50, ge=1, le=200),
) -> Page[AuditOut]:
    after = decode_cursor(cursor)
    rows = await service.list_entries(
        session,
        actor.scope,
        after_id=int(after) if after and after.isdigit() else None,
        limit=limit,
        action=action,
        actor=actor_name,
        target_id=target_id,
    )
    page = rows[:limit]
    return Page(
        items=[AuditOut.model_validate(r) for r in page],
        next_cursor=encode_cursor(page[-1].id) if len(rows) > limit else None,
    )


@router.post(
    "/verify", response_model=VerifyOut, summary="Walk the hash chain and the signed checkpoints"
)
async def verify(actor: StaffRead, container: ContainerDep, session: SessionDep) -> VerifyOut:
    await service.seal(session, actor.org_id)
    result = await service.verify(session, actor.org_id, container.keys)
    if not result.ok:
        log.error(
            "audit verification failed",
            extra={"org_id": str(actor.org_id), "problems": result.problems[:5]},
        )
    return VerifyOut(**result.as_dict())


@router.post(
    "/seal",
    response_model=CheckpointOut | None,
    summary="Seal pending records and sign a checkpoint now",
)
async def seal_now(
    actor: StaffWrite, container: ContainerDep, session: SessionDep
) -> AuditCheckpoint | None:
    await service.seal(session, actor.org_id)
    return await service.checkpoint(session, actor.org_id, container.keys, container.audit_storage)


@router.get(
    "/checkpoints",
    response_model=list[CheckpointOut],
    summary="Signed checkpoints of the chain head",
)
async def checkpoints(
    actor: StaffRead, session: SessionDep, limit: int = Query(50, ge=1, le=500)
) -> list[AuditCheckpoint]:
    rows = await session.scalars(
        select(AuditCheckpoint)
        .where(AuditCheckpoint.org_id == actor.org_id)
        .order_by(AuditCheckpoint.seq.desc())
        .limit(limit)
    )
    return list(rows.all())


@router.get("/export", summary="Every sealed record as JSON lines (for a SIEM or an auditor)")
async def export(actor: StaffRead, container: ContainerDep) -> StreamingResponse:
    async def lines() -> AsyncIterator[bytes]:
        async with container.db.sessionmaker() as session:
            stream = await session.stream_scalars(
                select(AuditLog)
                .where(AuditLog.org_id == actor.org_id, AuditLog.hash.is_not(None))
                .order_by(AuditLog.seq)
                .execution_options(yield_per=1000)
            )
            async for row in stream:
                yield orjson.dumps(AuditOut.model_validate(row).model_dump(mode="json")) + b"\n"

    return StreamingResponse(
        lines(),
        media_type="application/x-ndjson",
        headers={"content-disposition": 'attachment; filename="agentguard-audit.jsonl"'},
    )
