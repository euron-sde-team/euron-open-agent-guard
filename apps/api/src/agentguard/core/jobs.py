"""Background jobs in Postgres: a transactional outbox with leases.

A job is a row written in the same transaction as the change that needs it (an approval
request and its notification job commit together), so nothing the API accepted can lose its
follow-up work, whatever happens to Redis or a worker. ``NOTIFY`` on commit wakes idle
workers within milliseconds; a poll interval covers a missed notification.

Workers claim jobs with ``FOR UPDATE SKIP LOCKED`` and a lease. A worker that dies mid-job
stops extending its lease, so another worker reclaims the job after ``JOB_LEASE_S``. Every
claim increments ``attempts``; a handler writes its results through :meth:`JobContext.
fenced`, which locks the row and checks the attempt is still its own before committing, so
a worker that lost its lease (paused, partitioned) cannot write a second result.

Handlers must be idempotent anyway: an external side effect (an email, a webhook) made
before the fenced commit may be repeated once after a crash. Each one carries the job id
as its idempotency key.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import DateTime, Index, Integer, String, Text, func, select, text, update
from sqlalchemy.dialects.postgresql import JSONB, UUID, insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from agentguard.core.db import Base, new_id

if TYPE_CHECKING:
    from agentguard.core.container import Container

log = logging.getLogger("agentguard.jobs")

CHANNEL = "agentguard_jobs"
# Backoff before attempt n+1 (seconds); the last value repeats.
BACKOFF_S = (2, 10, 60, 300, 1800)


class Job(Base):
    __tablename__ = "jobs"
    __table_args__ = (
        # The claim query: queued jobs due now, and running jobs whose lease expired.
        Index("ix_jobs_claim", "status", "run_after"),
        Index(
            "ix_jobs_dedupe",
            "dedupe_key",
            unique=True,
            postgresql_where=text("dedupe_key IS NOT NULL"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    org_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    dedupe_key: Mapped[str | None] = mapped_column(String(200), nullable=True)
    # queued, running, done, dead
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="queued")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    run_after: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    worker: Mapped[str | None] = mapped_column(String(64))
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


async def enqueue(
    session: AsyncSession,
    kind: str,
    payload: dict[str, Any],
    *,
    org_id: uuid.UUID | None = None,
    dedupe_key: str | None = None,
    delay_s: float = 0,
    max_attempts: int = 5,
) -> None:
    """Add a job to the caller's transaction. It becomes visible, and wakes the workers,
    only when that transaction commits. A ``dedupe_key`` makes the enqueue idempotent."""
    run_after = datetime.now(UTC) + timedelta(seconds=delay_s)
    stmt = insert(Job).values(
        id=new_id(),
        org_id=org_id,
        kind=kind,
        payload=payload,
        dedupe_key=dedupe_key,
        run_after=run_after,
        max_attempts=max_attempts,
    )
    if dedupe_key is not None:
        stmt = stmt.on_conflict_do_nothing(
            index_elements=["dedupe_key"], index_where=text("dedupe_key IS NOT NULL")
        )
    await session.execute(stmt)
    await session.execute(text("SELECT pg_notify(:c, :k)"), {"c": CHANNEL, "k": kind})


class LostLeaseError(Exception):
    """Another worker owns the job now: this attempt must not write its result."""


class RetryLaterError(Exception):
    """A handler asks for another attempt (a dependency is down), without logging a stack."""


@dataclass
class JobContext:
    container: Container
    job_id: uuid.UUID
    kind: str
    org_id: uuid.UUID | None
    payload: dict[str, Any]
    attempt: int
    max_attempts: int
    finished: bool = field(default=False)

    @property
    def last_attempt(self) -> bool:
        return self.attempt >= self.max_attempts

    @asynccontextmanager
    async def fenced(self) -> AsyncIterator[AsyncSession]:
        """A session whose commit also marks this job done, but only while this attempt
        still owns it. Raises :class:`LostLeaseError` (and rolls back) otherwise."""
        async with self.container.db.sessionmaker() as session:
            row = await session.execute(
                select(Job.status, Job.attempts).where(Job.id == self.job_id).with_for_update()
            )
            current = row.one_or_none()
            if current is None or current.status != "running" or current.attempts != self.attempt:
                raise LostLeaseError(str(self.job_id))
            yield session
            await session.execute(
                update(Job)
                .where(Job.id == self.job_id)
                .values(status="done", finished_at=func.now(), lease_until=None, last_error=None)
            )
            await session.commit()
            self.finished = True


Handler = Callable[[JobContext], Awaitable[None]]
DeadHandler = Callable[[JobContext, str], Awaitable[None]]


@dataclass(frozen=True)
class JobType:
    handler: Handler
    # Called once when the last attempt fails: the place to escalate instead of dropping.
    on_dead: DeadHandler | None = None


_HANDLERS: dict[str, JobType] = {}


def handles(kind: str, *, on_dead: DeadHandler | None = None) -> Callable[[Handler], Handler]:
    def register(fn: Handler) -> Handler:
        _HANDLERS[kind] = JobType(fn, on_dead)
        return fn

    return register


def job_types() -> dict[str, JobType]:
    return dict(_HANDLERS)


async def bury_exhausted(session: AsyncSession, kinds: list[str]) -> list[Job]:
    """Jobs whose worker died on their last attempt (the lease ran out, attempts used up).

    A job that kills its worker (out of memory, SIGKILL) never reaches ``mark_failed``;
    without this it would be reclaimed forever and take down every worker in turn. Such
    jobs are marked dead here; the caller runs their ``on_dead`` handler.
    """
    now = datetime.now(UTC)
    rows = await session.scalars(
        update(Job)
        .where(
            Job.kind.in_(kinds),
            Job.status == "running",
            Job.lease_until < now,
            Job.attempts >= Job.max_attempts,
        )
        .values(
            status="dead",
            lease_until=None,
            finished_at=func.now(),
            last_error="the worker stopped during the last attempt (lease expired)",
        )
        .returning(Job)
    )
    jobs = list(rows)
    await session.commit()
    return jobs


async def claim(
    session: AsyncSession, worker: str, limit: int, lease_s: int, kinds: list[str]
) -> list[Job]:
    """Claim up to ``limit`` due jobs, and jobs whose worker's lease ran out while
    attempts remain (exhausted ones are buried by :func:`bury_exhausted`)."""
    now = datetime.now(UTC)
    due = (
        select(Job.id)
        .where(
            Job.kind.in_(kinds),
            ((Job.status == "queued") & (Job.run_after <= now))
            | (
                (Job.status == "running")
                & (Job.lease_until < now)
                & (Job.attempts < Job.max_attempts)
            ),
        )
        .order_by(Job.run_after)
        .limit(limit)
        .with_for_update(skip_locked=True)
    )
    rows = await session.scalars(
        update(Job)
        .where(Job.id.in_(due.scalar_subquery()))
        .values(
            status="running",
            attempts=Job.attempts + 1,
            lease_until=now + timedelta(seconds=lease_s),
            worker=worker,
        )
        .returning(Job)
    )
    jobs = list(rows)
    await session.commit()
    return jobs


async def extend_lease(
    session: AsyncSession, job_id: uuid.UUID, attempt: int, lease_s: int
) -> bool:
    result = await session.execute(
        update(Job)
        .where(Job.id == job_id, Job.status == "running", Job.attempts == attempt)
        .values(lease_until=datetime.now(UTC) + timedelta(seconds=lease_s))
        .returning(Job.id)
    )
    await session.commit()
    return result.scalar_one_or_none() is not None


async def mark_done(session: AsyncSession, job_id: uuid.UUID, attempt: int) -> None:
    await session.execute(
        update(Job)
        .where(Job.id == job_id, Job.status == "running", Job.attempts == attempt)
        .values(status="done", finished_at=func.now(), lease_until=None)
    )
    await session.commit()


async def mark_failed(
    session: AsyncSession, job_id: uuid.UUID, attempt: int, max_attempts: int, error: str
) -> bool:
    """Schedule a retry with backoff, or bury the job. True when it is now dead."""
    dead = attempt >= max_attempts
    delay = BACKOFF_S[min(attempt - 1, len(BACKOFF_S) - 1)]
    await session.execute(
        update(Job)
        .where(Job.id == job_id, Job.status == "running", Job.attempts == attempt)
        .values(
            status="dead" if dead else "queued",
            run_after=datetime.now(UTC) + timedelta(seconds=delay),
            lease_until=None,
            last_error=error[:2000],
            finished_at=func.now() if dead else None,
        )
    )
    await session.commit()
    return dead


async def queue_stats(session: AsyncSession) -> dict[str, int]:
    rows = await session.execute(select(Job.status, func.count()).group_by(Job.status))
    stats = {"queued": 0, "running": 0, "done": 0, "dead": 0}
    stats.update({status: int(count) for status, count in rows.tuples()})
    return stats


async def prune(session: AsyncSession, older_than: timedelta) -> int:
    """Delete finished jobs past retention (dead jobs are kept for inspection longer)."""
    cutoff = datetime.now(UTC) - older_than
    result = await session.execute(
        text("DELETE FROM jobs WHERE status = 'done' AND finished_at < :cutoff"),
        {"cutoff": cutoff},
    )
    await session.commit()
    return int(getattr(result, "rowcount", 0) or 0)
