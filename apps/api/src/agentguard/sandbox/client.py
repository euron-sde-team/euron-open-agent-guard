"""Client of the sandbox service (``agentguard_sandbox``), the only place untrusted code runs.

The API and the worker never execute submitted code. They send it to the sandbox service
(its own image, unprivileged, on an internal network) over HTTP with a shared token:

``POST /run`` with :class:`RunRequest`, answered with :class:`RunResult`.

Network: ``none`` gives the code no network at all. ``proxy`` gives it a loopback port
inside its own network namespace that is relayed to the egress proxy, authenticated as the
agent, so every connection is decided by the agent's network policy and recorded. The code
can reach the proxy and nothing else (not the API, not the database, not the metadata
service).
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from agentguard.core.container import Container

LANGUAGES = ("python", "node", "bash")
MAX_CODE_BYTES = 200_000


class Limits(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cpu_s: float = Field(5.0, gt=0, le=300)
    wall_s: float = Field(10.0, gt=0, le=900)
    memory_mb: int = Field(256, ge=16, le=8192)
    pids: int = Field(32, ge=1, le=1024)
    output_bytes: int = Field(1_000_000, ge=1024, le=50_000_000)
    file_bytes: int = Field(10_000_000, ge=1024, le=1_000_000_000)


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    language: Literal["python", "node", "bash"]
    code: str = Field(..., max_length=MAX_CODE_BYTES)
    stdin: str = Field("", max_length=1_000_000)
    # Extra files written to the scratch directory before the run (name -> content).
    files: dict[str, str] = Field(default_factory=dict, max_length=20)
    # Environment of the program (secrets injected by AgentGuard land here, never in code).
    env: dict[str, str] = Field(default_factory=dict, max_length=50)
    limits: Limits = Field(default_factory=Limits)
    network: Literal["none", "proxy"] = "none"
    # proxy mode: where the egress proxy listens and the Proxy-Authorization value the relay
    # adds (the agent's identity for the network policy). Never visible to the code.
    proxy_url: str | None = None
    proxy_authorization: str | None = None


class RunResult(BaseModel):
    # ok, nonzero_exit, timeout, memory, output_limit, killed, error.
    verdict: str
    exit_code: int | None = None
    signal: int | None = None
    stdout: str = ""
    stderr: str = ""
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    cpu_ms: int = 0
    wall_ms: int = 0
    memory_kb: int = 0
    detail: str | None = None


class SandboxUnavailableError(Exception):
    pass


async def run(container: Container, request: RunRequest) -> RunResult:
    settings = container.settings
    timeout = min(settings.sandbox_timeout_s, request.limits.wall_s + 15)
    try:
        resp = await container.http.post(
            f"{settings.sandbox_url.rstrip('/')}/run",
            json=request.model_dump(),
            headers={"authorization": f"Bearer {settings.sandbox_token}"},
            timeout=timeout,
        )
    except Exception as exc:
        raise SandboxUnavailableError(
            f"The sandbox service is unreachable ({type(exc).__name__})"
        ) from exc
    if resp.status_code != 200:
        raise SandboxUnavailableError(f"The sandbox service answered {resp.status_code}")
    return RunResult.model_validate(resp.json())
