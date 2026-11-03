"""Live events between processes: the worker posts an AI reply, every API replica holding a
WebSocket for that conversation hears about it.

Events are small invalidations (``{"type": "message.created", "ticket_id": ...}``), not
data: a client that receives one fetches what changed over REST, and a client that
reconnects fetches everything since its cursor. So a lost event delays an update, it never
loses a message, and the transport can be a lossy pub/sub.

Two transports, same interface:

* Redis pub/sub when ``REDIS_URL`` is set (one pattern subscription per process);
* Postgres ``LISTEN/NOTIFY`` otherwise, so a deployment without Redis still gets live
  updates across the API and the worker (payloads stay far under the 8 kB limit).

Each process holds one subscription and fans events out to local queues, so a thousand
open dashboards cost one Redis or Postgres connection, not a thousand.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections import defaultdict
from collections.abc import AsyncIterator
from typing import Any, Protocol

import asyncpg
import orjson
import redis.asyncio as aioredis

log = logging.getLogger("agentguard.hub")

PG_CHANNEL = "agentguard_events"
REDIS_PREFIX = "sd:ev:"
QUEUE_SIZE = 256


def org_topic(org_id: object) -> str:
    return f"org:{org_id}"


def ticket_topic(ticket_id: object) -> str:
    return f"ticket:{ticket_id}"


class Transport(Protocol):
    async def publish(self, topic: str, data: bytes) -> None: ...
    async def run(self, deliver: Any) -> None: ...
    async def close(self) -> None: ...


class RedisTransport:
    def __init__(self, url: str) -> None:
        self.redis = aioredis.Redis.from_url(url, socket_connect_timeout=2.0)

    async def publish(self, topic: str, data: bytes) -> None:
        await self.redis.publish(REDIS_PREFIX + topic, data)

    async def run(self, deliver: Any) -> None:
        pubsub = self.redis.pubsub()
        await pubsub.psubscribe(REDIS_PREFIX + "*")
        try:
            async for message in pubsub.listen():
                if message.get("type") != "pmessage":
                    continue
                channel = message["channel"]
                topic = (channel.decode() if isinstance(channel, bytes) else str(channel))[
                    len(REDIS_PREFIX) :
                ]
                deliver(topic, message["data"])
        finally:
            with contextlib.suppress(Exception):
                await pubsub.aclose()  # type: ignore[no-untyped-call]

    async def close(self) -> None:
        await self.redis.aclose()


def _pg_dsn(url: str) -> str:
    return url.replace("postgresql+asyncpg://", "postgresql://", 1)


class PostgresTransport:
    def __init__(self, database_url: str) -> None:
        self.dsn = _pg_dsn(database_url)
        self._pub: asyncpg.Connection | None = None
        self._lock = asyncio.Lock()

    async def publish(self, topic: str, data: bytes) -> None:
        async with self._lock:
            if self._pub is None or self._pub.is_closed():
                self._pub = await asyncpg.connect(self.dsn)
            payload = topic + "\n" + data.decode()
            await self._pub.execute("SELECT pg_notify($1, $2)", PG_CHANNEL, payload)

    async def run(self, deliver: Any) -> None:
        conn = await asyncpg.connect(self.dsn)
        closed = asyncio.Event()

        def on_notify(_c: object, _pid: int, _channel: str, payload: str) -> None:
            topic, _, data = payload.partition("\n")
            deliver(topic, data.encode())

        conn.add_termination_listener(lambda _c: closed.set())
        await conn.add_listener(PG_CHANNEL, on_notify)
        try:
            await closed.wait()
        finally:
            with contextlib.suppress(Exception):
                await conn.close()

    async def close(self) -> None:
        if self._pub is not None and not self._pub.is_closed():
            await self._pub.close()


class Hub:
    """Publish events to topics; subscribe local consumers to topics."""

    def __init__(self, transport: Transport) -> None:
        self.transport = transport
        self._subs: dict[str, set[asyncio.Queue[dict[str, Any]]]] = defaultdict(set)
        self._task: asyncio.Task[None] | None = None

    @classmethod
    def build(cls, redis_url: str, database_url: str) -> Hub:
        transport: Transport = (
            RedisTransport(redis_url) if redis_url else PostgresTransport(database_url)
        )
        return cls(transport)

    async def publish(self, topic: str, event: dict[str, Any]) -> None:
        """Best effort: a failed publish is logged, never raised into the caller, because
        the change it announces is already committed and clients re-sync on reconnect."""
        try:
            await self.transport.publish(topic, orjson.dumps(event))
        except Exception as exc:
            from agentguard.observability.metrics import DEPENDENCY_ERRORS

            DEPENDENCY_ERRORS.labels("hub", "publish").inc()
            log.warning("event publish failed", extra={"topic": topic, "error": type(exc).__name__})

    def _deliver(self, topic: str, data: bytes) -> None:
        queues = self._subs.get(topic)
        if not queues:
            return
        try:
            event = orjson.loads(data)
        except orjson.JSONDecodeError:
            return
        for queue in list(queues):
            if queue.full():
                # A stalled client must not hold memory: drop its oldest event. It will
                # re-sync from REST on the next event or reconnect.
                with contextlib.suppress(asyncio.QueueEmpty):
                    queue.get_nowait()
            queue.put_nowait(event)

    def _ensure_running(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._run(), name="hub-subscriber")

    async def _run(self) -> None:
        delay = 0.5
        while True:
            try:
                await self.transport.run(self._deliver)
                delay = 0.5
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning("event subscription lost", extra={"error": type(exc).__name__})
            await asyncio.sleep(delay)
            delay = min(delay * 2, 10)

    @contextlib.asynccontextmanager
    async def subscribe(self, *topics: str) -> AsyncIterator[asyncio.Queue[dict[str, Any]]]:
        self._ensure_running()
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(QUEUE_SIZE)
        for topic in topics:
            self._subs[topic].add(queue)
        try:
            yield queue
        finally:
            for topic in topics:
                self._subs[topic].discard(queue)
                if not self._subs[topic]:
                    del self._subs[topic]

    @property
    def subscriber_count(self) -> int:
        return sum(len(v) for v in self._subs.values())

    async def close(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._task
        await self.transport.close()
