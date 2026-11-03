"""Hostile sandbox suite: runs inside the sandbox image with production hardening.

``scripts/test-sandbox.sh`` builds the image and starts it with every capability dropped,
no-new-privileges, the custom seccomp profile, a read-only root, tmpfs scratch, pids and
memory limits and no network, then runs these tests against the real runner, nsjail and
toolchains. Anywhere nsjail is not installed they are collected and skipped.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import shutil
import tempfile
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from agentguard_sandbox.config import SandboxSettings
from agentguard_sandbox.nsjail import NsjailIsolator
from agentguard_sandbox.runner import Runner
from agentguard_sandbox.schemas import Limits, RunRequest, RunResult

NSJAIL = Path("/usr/local/bin/nsjail")
# The service's own secret. It is in this process's environment exactly as in production,
# so a program that could read the service's environment would find it.
SERVICE_TOKEN = "service-token-must-never-reach-the-program-0123456789"
PROXY_SECRET = "Bearer agent-egress-credential-the-code-must-not-see"


@pytest.fixture(scope="session")
def settings() -> Iterator[SandboxSettings]:
    os.environ["SANDBOX_TOKEN"] = SERVICE_TOKEN
    scratch = Path(tempfile.mkdtemp(prefix="agentguard-sandbox-test-"))
    yield SandboxSettings(
        sandbox_token=SERVICE_TOKEN,
        sandbox_scratch_dir=scratch,
        sandbox_concurrency=4,
    )
    shutil.rmtree(scratch, ignore_errors=True)


@pytest.fixture(scope="session")
def runner(settings: SandboxSettings) -> Runner:
    return Runner(settings, NsjailIsolator())


async def run(
    runner: Runner, language: str, code: str, *, limits: dict[str, Any] | None = None, **kw: Any
) -> RunResult:
    request = RunRequest(language=language, code=code, limits=Limits(**(limits or {})), **kw)
    return await runner.run(request)


SUM = {
    "python": "import sys\nprint(sum(int(x) for x in sys.stdin.read().split()))\n",
    "node": "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>console.log(s.trim().split(/\\s+/).map(Number).reduce((a,b)=>a+b,0)));\n",
    "bash": "read a b\necho $((a + b))\n",
}


async def assert_healthy(runner: Runner) -> None:
    """A normal run in every language still returns the right answer."""
    for language, code in SUM.items():
        result = await run(runner, language, code, stdin="40 2\n")
        assert result.verdict == "ok", (language, result)
        assert result.stdout.strip() == "42", (language, result)


@pytest.fixture
async def healthy_after(runner: Runner) -> AsyncIterator[None]:
    """Use in every hostile test: the next run after the abuse must still be correct."""
    yield
    await assert_healthy(runner)


def _response(body: bytes) -> bytes:
    head = f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    return head.encode() + body


@dataclass
class FakeProxy:
    """A stand-in for the egress proxy that records what reached it.

    CONNECT gets ``200``, then an HTTP answer to a request sent through the tunnel or an
    echo of anything else; an absolute-form GET gets a fixed body. Every request head is kept so tests can see the injected credential.
    """

    heads: list[list[str]] = field(default_factory=list)
    port: int = 0

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def authorizations(self) -> list[list[str]]:
        return [
            [
                line.split(":", 1)[1].strip()
                for line in head
                if line.lower().startswith("proxy-authorization:")
            ]
            for head in self.heads
        ]

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            raw = await reader.readuntil(b"\r\n\r\n")
            lines = raw.decode("latin-1").rstrip("\r\n").split("\r\n")
            self.heads.append(lines)
            if lines[0].startswith("CONNECT "):
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()
                while data := await reader.read(65536):
                    if data.startswith(b"GET "):
                        # Plain HTTP inside a tunnel (Node's fetch tunnels everything).
                        body = b"tunneled:" + data.split(b" ")[1]
                        writer.write(_response(body))
                    else:
                        writer.write(b"echo:" + data)
                    await writer.drain()
            else:
                writer.write(_response(b"proxied:" + lines[0].split(" ")[1].encode()))
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()


@pytest.fixture
async def fake_proxy() -> AsyncIterator[FakeProxy]:
    proxy = FakeProxy()
    server = await asyncio.start_server(proxy.handle, "127.0.0.1", 0)
    proxy.port = server.sockets[0].getsockname()[1]
    yield proxy
    server.close()
    await server.wait_closed()


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    skip = pytest.mark.skip(reason="needs the sandbox image (scripts/test-sandbox.sh)")
    for item in items:
        if "tests/sandbox/" in str(item.path).replace("\\", "/"):
            item.add_marker(pytest.mark.sandbox)
            if not NSJAIL.exists():
                item.add_marker(skip)
