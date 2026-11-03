"""WebSockets: live updates for the dashboard.

People connect to ``/ws/dashboard`` with their session cookie (checked on upgrade and again
on every ping, so a signed-out or disabled user is disconnected). Events are small
invalidations ("a decision", "an approval changed", "a threat"); the dashboard fetches what
changed over REST.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import Any

import orjson
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from agentguard.auth.dependencies import SESSION_COOKIE, is_revoked
from agentguard.core.container import Container
from agentguard.core.hub import org_topic
from agentguard.core.security import decode_session
from agentguard.observability.metrics import websockets
from agentguard.users.models import User

router = APIRouter()


async def _refuse(ws: WebSocket, code: int) -> None:
    """Accept, then close with an application code: a close before accept is a bare HTTP
    403 to the browser, which then cannot tell "sign in again" (4401) from a network error."""
    await ws.accept()
    await ws.close(code=code)


PING_S = 25


async def _pump(
    ws: WebSocket,
    container: Container,
    topics: list[str],
    on_client: Any,
    kind: str,
    still_valid: Any = None,
) -> None:
    websockets.labels(kind).inc()
    try:
        async with container.hub.subscribe(*topics) as queue:
            await ws.send_text(orjson.dumps({"type": "ready"}).decode())

            async def outbound() -> None:
                while True:
                    try:
                        event = await asyncio.wait_for(queue.get(), timeout=PING_S)
                    except TimeoutError:
                        if still_valid is not None and not await still_valid():
                            await ws.close(code=4401)  # signed out, disabled or revoked meanwhile
                            return
                        event = {"type": "ping"}
                    await ws.send_text(orjson.dumps(event).decode())

            async def inbound() -> None:
                while True:
                    raw = await ws.receive_text()
                    if len(raw) > 2000:
                        continue
                    try:
                        data = orjson.loads(raw)
                    except orjson.JSONDecodeError:
                        continue
                    if isinstance(data, dict):
                        await on_client(data)

            tasks = [asyncio.create_task(outbound()), asyncio.create_task(inbound())]
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task
            for task in done:
                with contextlib.suppress(WebSocketDisconnect, Exception):
                    task.result()
    finally:
        websockets.labels(kind).dec()


def _origin_ok(container: Container, ws: WebSocket) -> bool:
    origin = ws.headers.get("origin")
    return origin is None or origin in container.settings.cors_origins


@router.websocket("/ws/dashboard")
async def dashboard(ws: WebSocket) -> None:
    container: Container = ws.app.state.container
    if not _origin_ok(container, ws):
        await _refuse(ws, 4403)
        return
    token = ws.cookies.get(SESSION_COOKIE) or ws.query_params.get("token")
    claims = decode_session(token, container.settings.session_secret) if token else None
    if claims is None:
        await _refuse(ws, 4401)
        return
    async with container.db.sessionmaker() as session:
        user = await session.get(User, claims.user_id)
        if (
            user is None
            or user.disabled
            or user.session_version != claims.session_version
            or await is_revoked(session, claims)
        ):
            await _refuse(ws, 4401)
            return
        org_id = user.org_id

    async def still_valid() -> bool:
        async with container.db.sessionmaker() as s:
            fresh = await s.get(User, claims.user_id)
            return bool(
                fresh
                and not fresh.disabled
                and fresh.session_version == claims.session_version
                and not await is_revoked(s, claims)
            )

    async def ignore(_: dict[str, Any]) -> None:
        return None

    await ws.accept()
    await _pump(ws, container, [org_topic(org_id)], ignore, "dashboard", still_valid)
