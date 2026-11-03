"""Live events and webhooks that follow a committed change.

Services call :func:`emit` while they work; the events wait on the session and are
published by :func:`commit` only after the transaction commits, so a client is never told
about a message that a rollback then removed. Webhook deliveries are jobs written in the
same transaction (see ``integrations``), so they are as durable as the change itself.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy.ext.asyncio import AsyncSession

if TYPE_CHECKING:
    from agentguard.core.container import Container

_KEY = "agentguard.events"


def emit(session: AsyncSession, topic: str, event: dict[str, Any]) -> None:
    session.info.setdefault(_KEY, []).append((topic, event))


def pending(session: AsyncSession) -> list[tuple[str, dict[str, Any]]]:
    return list(session.info.get(_KEY, []))


async def publish_pending(container: Container, session: AsyncSession) -> None:
    events = session.info.pop(_KEY, [])
    seen: set[str] = set()
    for topic, event in events:
        key = f"{topic}|{sorted(event.items())}"
        if key in seen:
            continue  # one "ticket.updated" per ticket per commit is enough
        seen.add(key)
        await container.hub.publish(topic, event)


async def commit(container: Container, session: AsyncSession) -> None:
    await session.commit()
    await publish_pending(container, session)
