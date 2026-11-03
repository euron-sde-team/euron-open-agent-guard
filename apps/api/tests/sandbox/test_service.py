"""The HTTP service end to end in the image: the real app, nsjail and the token."""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest

from agentguard_sandbox.app import create_app
from agentguard_sandbox.config import SandboxSettings
from tests.sandbox.conftest import SERVICE_TOKEN


@pytest.fixture
async def client(settings: SandboxSettings) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://sandbox") as c:
            yield c


async def test_healthz_reports_nsjail(client: httpx.AsyncClient) -> None:
    resp = await client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["isolation"] == "nsjail"


async def test_run_over_http(client: httpx.AsyncClient) -> None:
    body = {"language": "python", "code": "print(6 * 7)"}
    denied = await client.post(
        "/run", json=body, headers={"authorization": "Bearer wrong-token-0000000"}
    )
    assert denied.status_code == 401
    resp = await client.post(
        "/run", json=body, headers={"authorization": f"Bearer {SERVICE_TOKEN}"}
    )
    assert resp.status_code == 200
    result = resp.json()
    assert result["verdict"] == "ok"
    assert result["stdout"] == "42\n"
    assert result["cpu_ms"] > 0 and result["memory_kb"] > 0
