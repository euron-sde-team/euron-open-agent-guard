"""Background worker: jobs (approvals, notifications, webhooks) and periodic tasks.

Stateless and safe to run as several replicas. Jobs are claimed from Postgres with
``FOR UPDATE SKIP LOCKED`` (see ``core/jobs.py``); ``LISTEN`` wakes the worker the moment
one is committed, and a poll interval covers a missed notification. Each running job's
lease is extended by a heartbeat while it runs; a worker that dies stops heart-beating
and another replica reclaims its jobs. Periodic tasks run under a Postgres advisory lock,
so each runs on one replica at a time. SIGTERM stops claiming, lets running jobs finish
(up to the lease), then exits. Prometheus metrics on WORKER_METRICS_PORT.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import signal
import socket
import time
import uuid

import asyncpg
from prometheus_client import start_http_server
from sqlalchemy import text

from agentguard.core import jobs
from agentguard.core.config import Settings, get_settings
from agentguard.core.container import Container
from agentguard.core.db import import_all_models
from agentguard.core.logs import configure_logging
from agentguard.core.tasks import Task, tasks
from agentguard.observability import metrics

log = logging.getLogger("agentguard.worker")
# The most a periodic task may run before it is cancelled.
TASK_BUDGET_S = 240


def import_handlers() -> None:
    """Register every job handler and periodic task (their modules register on import)."""
    from agentguard import background as _background  # noqa: F401
    from agentguard.approvals import service as _approvals  # noqa: F401
    from agentguard.integrations import service as _integrations  # noqa: F401


class Worker:
    def __init__(self, container: Container, name: str | None = None) -> None:
        self.container = container
        self.settings: Settings = container.settings
        self.name = name or f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:4]}"
        self.wake = asyncio.Event()
        self.stopping = asyncio.Event()
        self.slots = asyncio.Semaphore(self.settings.worker_concurrency)
        self.running: set[asyncio.Task[None]] = set()
        self.last_run: dict[str, float] = {}
        self.periodic_tasks: dict[str, asyncio.Task[None]] = {}

    async def listen(self) -> None:
        """Set ``wake`` whenever a job is committed (pg_notify in ``jobs.enqueue``)."""
        dsn = self.settings.database_url.replace("postgresql+asyncpg://", "postgresql://", 1)
        while not self.stopping.is_set():
            try:
                conn = await asyncpg.connect(dsn)
                closed = asyncio.Event()
                conn.add_termination_listener(lambda _c, done=closed: done.set())
                await conn.add_listener(jobs.CHANNEL, lambda *_: self.wake.set())
                try:
                    stop = asyncio.create_task(self.stopping.wait())
                    lost = asyncio.create_task(closed.wait())
                    await asyncio.wait([stop, lost], return_when=asyncio.FIRST_COMPLETED)
                    stop.cancel()
                    lost.cancel()
                finally:
                    with contextlib.suppress(Exception):
                        await conn.close()
            except (OSError, asyncpg.PostgresError) as exc:
                log.warning(
                    "job notifications unavailable, polling", extra={"error": type(exc).__name__}
                )
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(self.stopping.wait(), timeout=5)

    async def run_job(self, job: jobs.Job) -> None:
        types = jobs.job_types()
        job_type = types[job.kind]
        ctx = jobs.JobContext(
            self.container,
            job.id,
            job.kind,
            job.org_id,
            job.payload,
            job.attempts,
            job.max_attempts,
        )
        started = time.perf_counter()
        heartbeat = asyncio.create_task(self.heartbeat(ctx))
        result = "done"
        try:
            await job_type.handler(ctx)
            if not ctx.finished:
                async with self.container.db.sessionmaker() as session:
                    await jobs.mark_done(session, job.id, job.attempts)
        except jobs.LostLeaseError:
            result = "lost_lease"
            log.warning("job lease lost", extra={"job": str(job.id), "kind": job.kind})
        except Exception as exc:
            result = "retry"
            if isinstance(exc, jobs.RetryLaterError):
                log.info(
                    "job will retry",
                    extra={"job": str(job.id), "kind": job.kind, "error": str(exc)[:300]},
                )
            else:
                log.exception("job failed", extra={"job": str(job.id), "kind": job.kind})
            async with self.container.db.sessionmaker() as session:
                dead = await jobs.mark_failed(
                    session, job.id, job.attempts, job.max_attempts, f"{type(exc).__name__}: {exc}"
                )
            if dead:
                result = "dead"
                if job_type.on_dead is not None:
                    try:
                        await job_type.on_dead(ctx, str(exc))
                    except Exception:
                        log.exception(
                            "dead-job handler failed", extra={"job": str(job.id), "kind": job.kind}
                        )
        finally:
            heartbeat.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await heartbeat
            metrics.jobs_processed.labels(job.kind, result).inc()
            metrics.job_seconds.labels(job.kind).observe(time.perf_counter() - started)
            self.slots.release()

    async def dead_letter(self, job: jobs.Job) -> None:
        """A job whose worker died on its last attempt: its fallback still runs (an AI
        turn is handed to a person instead of being left unanswered)."""
        metrics.jobs_processed.labels(job.kind, "dead").inc()
        log.error("job buried after its worker died", extra={"job": str(job.id), "kind": job.kind})
        job_type = jobs.job_types().get(job.kind)
        if job_type is None or job_type.on_dead is None:
            return
        ctx = jobs.JobContext(
            self.container,
            job.id,
            job.kind,
            job.org_id,
            job.payload,
            job.attempts,
            job.max_attempts,
        )
        try:
            await job_type.on_dead(ctx, job.last_error or "worker died")
        except Exception:
            log.exception("dead-job handler failed", extra={"job": str(job.id), "kind": job.kind})

    async def heartbeat(self, ctx: jobs.JobContext) -> None:
        lease = self.settings.job_lease_s
        while True:
            await asyncio.sleep(lease / 3)
            async with self.container.db.sessionmaker() as session:
                if not await jobs.extend_lease(session, ctx.job_id, ctx.attempt, lease):
                    return

    async def claim_batch(self) -> int:
        free = self.settings.worker_concurrency - len(self.running)
        if free <= 0:
            return 0
        kinds = list(jobs.job_types())
        async with self.container.db.sessionmaker() as session:
            buried = await jobs.bury_exhausted(session, kinds)
            claimed = await jobs.claim(session, self.name, free, self.settings.job_lease_s, kinds)
        for job in buried:
            await self.dead_letter(job)
        for job in claimed:
            await self.slots.acquire()
            task = asyncio.create_task(self.run_job(job), name=f"job-{job.kind}")
            self.running.add(task)
            task.add_done_callback(self.running.discard)
        return len(claimed)

    async def run_periodic(self, task: Task) -> None:
        async with self.container.db.engine.connect() as conn:
            got = await conn.scalar(text("SELECT pg_try_advisory_lock(:k)"), {"k": task.lock_id})
            if not got:
                return
            try:
                # A time budget: one stuck dependency must not hold the task's lock forever.
                handled = await asyncio.wait_for(task.fn(self.container), timeout=TASK_BUDGET_S)
                if handled:
                    log.info("task done", extra={"task": task.name, "items": handled})
            except TimeoutError:
                log.warning("task ran out of time", extra={"task": task.name})
            except Exception:
                log.exception("task failed", extra={"task": task.name})
            finally:
                await conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": task.lock_id})
                await conn.commit()

    async def periodic(self) -> None:
        """Start due periodic tasks in the background: they never delay job claiming."""
        now = time.monotonic()
        for task in tasks().values():
            running = self.periodic_tasks.get(task.name)
            if running is not None and not running.done():
                continue
            if now - self.last_run.get(task.name, 0.0) >= task.every_s:
                self.last_run[task.name] = now
                self.periodic_tasks[task.name] = asyncio.create_task(
                    self.run_periodic(task), name=f"periodic-{task.name}"
                )

    async def run(self) -> None:
        listener = asyncio.create_task(self.listen())
        log.info("worker started", extra={"worker": self.name, "kinds": sorted(jobs.job_types())})
        try:
            while not self.stopping.is_set():
                self.wake.clear()
                try:
                    claimed = await self.claim_batch()
                    await self.periodic()
                except Exception:
                    log.exception("worker loop failed")
                    claimed = 0
                if claimed and len(self.running) < self.settings.worker_concurrency:
                    continue  # more may be waiting: claim again at once, no sleep
                waits = [
                    asyncio.create_task(self.wake.wait()),
                    asyncio.create_task(self.stopping.wait()),
                ]
                if self.running:
                    waits.append(asyncio.ensure_future(asyncio.wait(set(self.running))))  # type: ignore[arg-type]
                await asyncio.wait(
                    waits,
                    timeout=self.settings.worker_poll_interval_s,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for w in waits:
                    w.cancel()
        finally:
            if self.running:
                await asyncio.wait(set(self.running), timeout=self.settings.job_lease_s)
            for t in self.periodic_tasks.values():
                t.cancel()
            listener.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await listener


async def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)
    import_all_models()
    import_handlers()
    if settings.worker_metrics_port:
        start_http_server(settings.worker_metrics_port)
    container = Container.build(settings)
    worker = Worker(container)
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, worker.stopping.set)
    try:
        await worker.run()
    finally:
        await container.close()
        log.info("worker stopped")


def run() -> None:
    asyncio.run(main())
