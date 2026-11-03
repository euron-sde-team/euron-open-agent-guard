"""Health, readiness, metrics and deployment info."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable
from typing import Any

from fastapi import APIRouter, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import text

from agentguard import __version__
from agentguard.auth.dependencies import OrgAdmin
from agentguard.core.deps import ContainerDep, SessionDep
from agentguard.core.jobs import queue_stats
from agentguard.core.schemas import ApiModel

router = APIRouter(tags=["system"])


@router.get("/healthz", summary="Liveness")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/health", summary="Liveness (alias of /healthz)")
async def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


async def _probe(name: str, coro: Awaitable[Any]) -> tuple[str, dict[str, Any]]:
    t0 = time.perf_counter()
    try:
        await asyncio.wait_for(coro, timeout=2)
        return name, {"ok": True, "ms": round((time.perf_counter() - t0) * 1000, 1)}
    except Exception as exc:
        return name, {"ok": False, "error": type(exc).__name__}


@router.get("/readyz", summary="Readiness: Postgres reachable (Redis reported too)")
async def readyz(container: ContainerDep, response: Response) -> dict[str, Any]:
    async def pg() -> None:
        async with container.db.engine.connect() as conn:
            await conn.execute(text("select 1"))

    probes = [_probe("postgres", pg())]
    if container.kv.backend == "redis":
        probes.append(_probe("redis", container.kv.ping()))
    checks = dict(await asyncio.gather(*probes))
    # Without Redis the API still works (caches and live updates fall back to memory and
    # Postgres), so Postgres alone decides readiness and Redis reports as degraded.
    ok = checks["postgres"]["ok"]
    response.status_code = 200 if ok else 503
    degraded = not all(c["ok"] for c in checks.values())
    return {"status": "degraded" if degraded else "ready", "checks": checks}


@router.get("/metrics", summary="Prometheus metrics", include_in_schema=False)
async def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


class SystemInfo(ApiModel):
    version: str
    environment: str
    storage: str
    key_mode: str
    cache: str
    mail: str
    redis: bool
    jobs: dict[str, int]
    live_connections: int


@router.get(
    "/api/v1/system", response_model=SystemInfo, tags=["system"], summary="Deployment status"
)
async def system(_: OrgAdmin, session: SessionDep, container: ContainerDep) -> SystemInfo:
    s = container.settings
    redis_ok = False
    if container.kv.backend == "redis":
        try:
            await container.kv.ping()
            redis_ok = True
        except Exception:
            redis_ok = False
    return SystemInfo(
        version=__version__,
        environment=s.environment,
        storage=s.storage,
        key_mode=s.key_mode,
        cache=s.cache_backend,
        mail=s.mail_backend,
        redis=redis_ok,
        jobs=await queue_stats(session),
        live_connections=container.hub.subscriber_count,
    )
