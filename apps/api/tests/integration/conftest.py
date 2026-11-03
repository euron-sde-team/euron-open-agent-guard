"""Integration harness: the real API, the real worker and the mock services, each served on
its own thread and event loop, against real Postgres and Redis (and OPA, Vault, the sandbox
and Floci when their URLs are given).

    make test-integration      (starts the services it needs)

Every test signs up its own organisation, so tests are isolated by tenant, which also
exercises tenant scoping on every request. The database is dropped and rebuilt by the
migrations once per run (so the migrations are tested too). The suite refuses any database
whose name does not contain "test" and any non-local host unless ALLOW_REMOTE_TEST_DB=true.

The option matrix (``make test-matrix``) reruns the suite with KEY_MODE local|kms,
TEST_SECRET_STORE database|vault and Redis on|off (TEST_REDIS_URL empty).
"""

from __future__ import annotations

import asyncio
import os
import socket
import threading
import time
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
import pytest
import redis.asyncio as aioredis
import uvicorn
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from agentguard.core.config import Settings

TEST_DB = os.environ.get(
    "TEST_DATABASE_URL", "postgresql+asyncpg://agentguard:agentguard@localhost:5142/agentguard_test"
)
TEST_REDIS = os.environ.get("TEST_REDIS_URL", "redis://localhost:5179/15")
SECRET_STORE = os.environ.get("TEST_SECRET_STORE", "database")
OPA_URL = os.environ.get("TEST_OPA_URL", "")
VAULT_URL = os.environ.get("TEST_VAULT_URL", "")
VAULT_TOKEN = os.environ.get("TEST_VAULT_TOKEN", "")
SANDBOX_URL = os.environ.get("TEST_SANDBOX_URL", "")
SANDBOX_TOKEN = os.environ.get("TEST_SANDBOX_TOKEN", "")
CSRF = {"x-agentguard-csrf": "1"}
PASSWORD = "Test-Pass-12345"


def _guard(url: str) -> None:
    parsed = urlparse(url.replace("+asyncpg", ""))
    if "test" not in (parsed.path or ""):
        raise RuntimeError(f"refusing {parsed.path!r}: the test database name must contain 'test'")
    if (
        parsed.hostname not in ("localhost", "127.0.0.1", "postgres")
        and os.environ.get("ALLOW_REMOTE_TEST_DB") != "true"
    ):
        raise RuntimeError("refusing a non-local test database (set ALLOW_REMOTE_TEST_DB=true)")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class Served:
    """An ASGI app (or import string) served by uvicorn on a thread, with its own loop."""

    def __init__(self, app: Any, port: int | None = None, factory: bool = False) -> None:
        self.port = port or free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        config = uvicorn.Config(
            app,
            host="127.0.0.1",
            port=self.port,
            log_level="warning",
            ws="websockets",
            factory=factory,
        )
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def start(self, health: str = "/healthz") -> Served:
        self.thread.start()
        deadline = time.time() + 60
        while time.time() < deadline:
            try:
                if httpx.get(self.url + health, timeout=1).status_code < 500:
                    return self
            except httpx.HTTPError:
                pass
            time.sleep(0.1)
        raise RuntimeError(f"server on {self.url} did not start")

    def stop(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=15)


class WorkerThread:
    """The real background worker on its own thread and event loop."""

    def __init__(self, settings: Settings, name: str = "test-worker") -> None:
        self.settings = settings
        self.name = name
        self.loop = asyncio.new_event_loop()
        self.worker: Any = None
        self.ready = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self._main())

    async def _main(self) -> None:
        from agentguard.core.container import Container
        from agentguard.worker import Worker, import_handlers

        import_handlers()
        container = Container.build(self.settings)
        self.worker = Worker(container, self.name)
        self.ready.set()
        try:
            await self.worker.run()
        finally:
            await container.close()

    def start(self) -> WorkerThread:
        self.thread.start()
        self.ready.wait(30)
        return self

    def stop(self) -> None:
        if self.worker is not None:
            self.loop.call_soon_threadsafe(self.worker.stopping.set)
        self.thread.join(timeout=30)


@pytest.fixture(scope="session")
def mock() -> Iterator[str]:
    served = Served("mockai.app:app").start()
    yield served.url
    served.stop()


@pytest.fixture(scope="session")
async def database() -> AsyncIterator[str]:
    """A fresh database built by the migrations."""
    _guard(TEST_DB)
    admin_url = TEST_DB.rsplit("/", 1)[0] + "/postgres"
    name = TEST_DB.rsplit("/", 1)[1]
    engine = create_async_engine(admin_url, isolation_level="AUTOCOMMIT")
    async with engine.connect() as conn:
        await conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        await conn.execute(text(f'CREATE DATABASE "{name}"'))
    await engine.dispose()
    from agentguard.migrations.runner import upgrade

    await asyncio.to_thread(upgrade, TEST_DB)
    if TEST_REDIS:
        r = aioredis.Redis.from_url(TEST_REDIS)
        await r.flushdb()
        await r.aclose()
    yield TEST_DB


def make_settings(database: str, tmp: Path, api_url: str, **overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "environment": "test",
        "database_url": database,
        "redis_url": TEST_REDIS,
        "session_secret": "test-only-session-secret-with-32-plus-bytes",
        "token_pepper": "test-only-token-pepper-with-32-plus-bytes!",
        "local_master_key": "test-only-master-key-with-32-plus-bytes-ok",
        "local_storage_dir": str(tmp / "objects"),
        "public_url": "http://localhost:5110",
        "public_api_url": api_url,
        "cors_origins": ["http://localhost:5110"],
        "mail_backend": "log",
        "allow_private_urls": True,
        "ai_allow_private_endpoints": True,
        "ai_timeout_s": 5,
        "worker_poll_interval_s": 0.3,
        "job_lease_s": 10,
        "signup_rpm": 10_000,
        "login_rpm": 10_000,
        "token_rpm": 100_000,
        "opa_url": OPA_URL,
        "vault_url": VAULT_URL,
        "vault_token": VAULT_TOKEN,
        "sandbox_url": SANDBOX_URL or "http://127.0.0.1:9",
        "sandbox_token": SANDBOX_TOKEN or "test-sandbox-token",
        "env_secret_allowlist": ["AGENTGUARD_TEST_ENV_SECRET"],
        "stdio_allowed_commands": ["python3"],
        "credential_rotation_grace_s": 60,
        "key_mode": os.environ.get("KEY_MODE", "local"),
        "storage": os.environ.get("TEST_STORAGE", "local"),
        "aws_endpoint_url": os.environ.get("TEST_AWS_ENDPOINT"),
        "s3_force_path_style": True,
        "kms_key_id": os.environ.get("TEST_KMS_KEY_ID", "alias/agentguard-local"),
        "objects_bucket": os.environ.get("TEST_OBJECTS_BUCKET", "agentguard-local-objects"),
    }
    values.update(overrides)
    return Settings(**values)


@dataclass
class Agent:
    """An agent with its credentials and a client carrying a fresh access token."""

    org: OrgHelper
    id: str
    slug: str
    client_id: str
    client_secret: str
    signing_secret: str
    client: httpx.AsyncClient

    async def authorize(self, tool: str, action: str = "call", **body: Any) -> dict[str, Any]:
        resp = await self.client.post(
            "/api/v1/authorize", json={"tool": tool, "action": action, **body}
        )
        assert resp.status_code == 200, resp.text
        result: dict[str, Any] = resp.json()
        return result

    async def execute(self, tool: str, action: str = "call", **body: Any) -> dict[str, Any]:
        resp = await self.client.post(
            "/api/v1/execute", json={"tool": tool, "action": action, **body}
        )
        assert resp.status_code == 200, resp.text
        result: dict[str, Any] = resp.json()
        return result


@dataclass
class OrgHelper:
    stack: Stack
    client: httpx.AsyncClient
    admin: dict[str, Any]
    email: str
    slug: str
    org_id: str
    agents: dict[str, Agent] = field(default_factory=dict)

    async def ok(
        self, method: str, path: str, json: Any = None, status: int = 200, **kw: Any
    ) -> Any:
        resp = await self.client.request(method, path, json=json, **kw)
        assert resp.status_code == status, f"{method} {path}: {resp.status_code} {resp.text}"
        return resp.json() if resp.content else None

    async def role(
        self, name: str, *permissions: tuple[str, list[str], str], inherits: list[str] | None = None
    ) -> dict[str, Any]:
        body = {
            "name": name,
            "inherits": inherits or [],
            "permissions": [{"tool": t, "actions": a, "resource": r} for t, a, r in permissions],
        }
        result: dict[str, Any] = await self.ok("POST", "/api/v1/roles", body, status=201)
        return result

    async def tool(self, name: str, kind: str = "function", **body: Any) -> dict[str, Any]:
        result: dict[str, Any] = await self.ok(
            "POST", "/api/v1/tools/register", {"name": name, "kind": kind, **body}, status=201
        )
        return result

    async def policy(self, source: str, activate: bool = True) -> dict[str, Any]:
        result: dict[str, Any] = await self.ok(
            "POST", "/api/v1/policies", {"source": source, "activate": activate}, status=201
        )
        return result

    async def secret(self, name: str, value: str, **body: Any) -> dict[str, Any]:
        store = body.pop("store", SECRET_STORE)
        result: dict[str, Any] = await self.ok(
            "POST",
            "/api/v1/secrets",
            {"name": name, "value": value, "store": store, **body},
            status=201,
        )
        return result

    async def agent(self, slug: str, roles: list[str] | None = None, **body: Any) -> Agent:
        data = await self.ok(
            "POST",
            "/api/v1/agents/register",
            {"slug": slug, "name": slug.replace("-", " ").title(), "roles": roles or [], **body},
            status=201,
        )
        cred = data["credential"]
        agent = Agent(
            self,
            data["agent"]["id"],
            slug,
            cred["client_id"],
            cred["client_secret"],
            cred["signing_secret"],
            self.stack.client(),
        )
        await self.refresh(agent)
        self.agents[slug] = agent
        return agent

    async def refresh(self, agent: Agent) -> str:
        resp = await self.stack.client().post(
            "/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": agent.client_id,
                "client_secret": agent.client_secret,
            },
        )
        assert resp.status_code == 200, resp.text
        token = str(resp.json()["access_token"])
        agent.client.headers["authorization"] = f"Bearer {token}"
        return token

    async def person(self, role: str) -> httpx.AsyncClient:
        """Invite someone with this role, accept, and return their signed-in client."""
        from agentguard.core.mail import OUTBOX

        email = f"{role}-{time.monotonic_ns()}@acme.test"
        await self.ok("POST", "/api/v1/invitations", {"email": email, "role": role}, status=201)
        mail = next(m for m in reversed(OUTBOX) if m.to == email)
        token = mail.text.split("token=")[1].split()[0]
        client = self.stack.client(**CSRF)
        resp = await client.post(
            "/api/v1/auth/invitations/accept",
            json={"token": token, "name": f"{role.title()} Person", "password": PASSWORD},
        )
        assert resp.status_code == 201, resp.text
        client.headers["authorization"] = f"Bearer {resp.json()['session_token']}"
        client.user = resp.json()["user"]  # type: ignore[attr-defined]
        return client

    async def api_key(self, scope: str = "read") -> str:
        data = await self.ok(
            "POST",
            "/api/v1/api-keys",
            {"name": f"key-{scope}-{time.monotonic_ns()}", "scope": scope},
            status=201,
        )
        return str(data["key"])

    async def wait_sealed(self, wait_s: float = 15) -> dict[str, Any]:
        deadline = time.monotonic() + wait_s
        while True:
            result: dict[str, Any] = await self.ok("POST", "/api/v1/audit-logs/verify")
            if result["unsealed"] == 0 or time.monotonic() > deadline:
                return result
            await asyncio.sleep(0.3)


@dataclass
class Stack:
    api_url: str
    settings: Settings
    mock_url: str
    worker: WorkerThread

    def client(self, **headers: str) -> httpx.AsyncClient:
        return httpx.AsyncClient(base_url=self.api_url, timeout=30, headers=headers)

    async def org(self, name: str = "Acme") -> OrgHelper:
        client = self.client(**CSRF)
        email = f"admin-{time.monotonic_ns()}@acme.test"
        resp = await client.post(
            "/api/v1/auth/signup",
            json={"org_name": name, "name": "Ada Admin", "email": email, "password": PASSWORD},
        )
        assert resp.status_code == 201, resp.text
        data = resp.json()
        client.headers["authorization"] = f"Bearer {data['session_token']}"
        org = await client.get("/api/v1/org")
        return OrgHelper(self, client, data["user"], email, data["org_slug"], org.json()["id"])

    async def calls(self, tool: str | None = None) -> list[dict[str, Any]]:
        async with httpx.AsyncClient() as http:
            resp = await http.get(
                f"{self.mock_url}/_calls", params={"tool": tool} if tool else None
            )
            result: list[dict[str, Any]] = resp.json()
            return result


@pytest.fixture(scope="session")
def stack(database: str, mock: str, tmp_path_factory: pytest.TempPathFactory) -> Iterator[Stack]:
    port = free_port()
    api_url = f"http://127.0.0.1:{port}"
    settings = make_settings(database, tmp_path_factory.mktemp("agentguard"), api_url)
    from agentguard.main import create_app

    api = Served(create_app(settings), port=port).start()
    worker = WorkerThread(settings).start()
    yield Stack(api.url, settings, mock, worker)
    worker.stop()
    api.stop()


@pytest.fixture
async def org(stack: Stack) -> OrgHelper:
    return await stack.org()
