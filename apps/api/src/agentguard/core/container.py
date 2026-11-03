"""Process-wide services, built once in the app lifespan (or the worker) and shared.

Holding them in one object (on ``app.state``) instead of module globals keeps the app
factory re-entrant and lets tests build an isolated container per app.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx

from agentguard import __version__
from agentguard.core.aws import aws_client
from agentguard.core.config import Settings
from agentguard.core.db import Database
from agentguard.core.hub import Hub
from agentguard.core.kv import KV, create_kv
from agentguard.core.sealing import KeySealer, KmsSealer, LocalSealer
from agentguard.core.storage import LocalStorage, ObjectStorage, S3Storage
from agentguard.identity.keys import KeyRing


def build_http_client(timeout_s: float) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=httpx.Timeout(timeout_s, connect=5.0),
        limits=httpx.Limits(max_connections=200, max_keepalive_connections=40),
        # Redirects are followed by hand where allowed, so every hop is checked.
        follow_redirects=False,
        headers={"user-agent": f"EuronOpenAgentGuard/{__version__}"},
    )


@dataclass
class Container:
    settings: Settings
    db: Database
    kv: KV
    # Outbound calls AgentGuard makes on an agent's behalf (HTTP tools) and its own
    # (webhooks, classifier, OPA, TokenShield, Vault). Every one goes through core.net checks.
    http: httpx.AsyncClient
    sealer: KeySealer
    storage: ObjectStorage
    hub: Hub
    keys: KeyRing
    # Where signed audit checkpoints are exported (the locked bucket on AWS).
    audit_storage: ObjectStorage
    # Lazily built clients for optional backends (Secrets Manager, the MCP upstream pool).
    extras: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def build(cls, settings: Settings) -> Container:
        sealer: KeySealer = (
            KmsSealer(aws_client(settings, "kms"), settings.kms_key_id)
            if settings.key_mode == "kms"
            else LocalSealer(settings.local_master_key)
        )
        storage: ObjectStorage = (
            S3Storage(aws_client(settings, "s3"), settings.objects_bucket)
            if settings.storage == "s3"
            else LocalStorage(settings.local_storage_dir)
        )
        db = Database(
            settings.database_url,
            pool_size=settings.db_pool_size,
            max_overflow=settings.db_max_overflow,
        )
        return cls(
            settings=settings,
            db=db,
            kv=create_kv(settings.redis_url, settings.memory_cache_max_bytes),
            http=build_http_client(30.0),
            sealer=sealer,
            storage=storage,
            hub=Hub.build(settings.redis_url, settings.database_url),
            keys=KeyRing(db.sessionmaker, sealer),
            audit_storage=S3Storage(aws_client(settings, "s3"), settings.audit_bucket)
            if settings.storage == "s3" and settings.audit_bucket
            else storage,
        )

    async def close(self) -> None:
        pool = self.extras.pop("mcp_pool", None)
        if pool is not None:
            await pool.close()
        await self.hub.close()
        await self.http.aclose()
        await self.kv.close()
        await self.db.dispose()
