"""Unit tests of the sandbox service that need neither nsjail, Docker nor the network.

The isolation itself is proven by the hostile suite inside the real image
(``scripts/test-sandbox.sh``). These cover the contract, validation, the token and body
gate, the proxy header rewrite, the environment, verdicts and the nsjail command line.
"""

from __future__ import annotations

import json
import signal
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from agentguard.sandbox import client
from agentguard_sandbox import schemas
from agentguard_sandbox.app import create_app, select_isolator, token_matches
from agentguard_sandbox.config import SandboxSettings
from agentguard_sandbox.fallback import DevFallbackIsolator
from agentguard_sandbox.isolation import Execution, RunSpec
from agentguard_sandbox.languages import LANGUAGES
from agentguard_sandbox.nsjail import NsjailIsolator
from agentguard_sandbox.process import Supervised, read_usage, supervise
from agentguard_sandbox.relay import BadRequestError, rewrite_head
from agentguard_sandbox.runner import Runner, program_env
from agentguard_sandbox.verdict import classify

TOKEN = "unit-test-sandbox-token-0123456789"


def settings(tmp_path: Path, **kw: Any) -> SandboxSettings:
    return SandboxSettings(
        sandbox_token=TOKEN,
        sandbox_scratch_dir=tmp_path / "scratch",
        nsjail_path=tmp_path / "no-nsjail",
        **kw,
    )


def supervised(**kw: Any) -> Supervised:
    base: dict[str, Any] = {
        "exit_code": 0,
        "signal": None,
        "cpu_ms": 10,
        "wall_ms": 12,
        "memory_kb": 9000,
        "stdout": b"42\n",
        "stderr": b"",
        "stdout_truncated": False,
        "stderr_truncated": False,
        "stopped": None,
    }
    return Supervised(**{**base, **kw})


class FakeIsolator:
    """Records the spec it was given and answers with a fixed execution."""

    name = "fake"
    supports_proxy = True

    def __init__(self, execution: Execution | None = None) -> None:
        self.execution = execution or Execution(process=supervised())
        self.specs: list[RunSpec] = []

    def execute(self, spec: RunSpec) -> Execution:
        self.specs.append(spec)
        assert (spec.input_dir / spec.language.filename).exists()
        return self.execution


# The contract


@pytest.mark.parametrize(
    ("ours", "theirs"),
    [
        (schemas.Limits, client.Limits),
        (schemas.RunRequest, client.RunRequest),
        (schemas.RunResult, client.RunResult),
    ],
)
def test_the_wire_contract_matches_the_api_client(ours: Any, theirs: Any) -> None:
    def shape(model: Any) -> dict[str, Any]:
        schema: dict[str, Any] = model.model_json_schema()
        schema.pop("title", None)
        schema.pop("description", None)
        return schema

    assert shape(ours) == shape(theirs)


def test_a_client_request_is_accepted_as_is() -> None:
    request = client.RunRequest(
        language="node",
        code="console.log(1)",
        env={"API_KEY": "x"},
        files={"data/a.csv": "1,2"},
        network="proxy",
        proxy_url="http://egress:5128",
        proxy_authorization="Bearer abc",
    )
    parsed = schemas.RunRequest.model_validate(request.model_dump())
    assert parsed.proxy_address() == ("egress", 5128)


# Validation


@pytest.mark.parametrize(
    "change",
    [
        {"env": {"1BAD": "x"}},
        {"env": {"OK": "a\x00b"}},
        {"env": {"OK": "x" * 40_000}},
        {"files": {"../escape": "x"}},
        {"files": {"/etc/passwd": "x"}},
        {"files": {"a//b": "x"}},
        {"files": {"main.py": "overwrite the code"}},
        {"files": {"a/../b": "x"}},
        {
            "proxy_authorization": "Bearer x\r\nX-Injected: 1",
            "network": "proxy",
            "proxy_url": "http://e:1",
        },
        {"network": "proxy"},
        {"network": "proxy", "proxy_url": "https://egress:5128"},
        {"network": "proxy", "proxy_url": "http://user:pw@egress:5128"},
        {"network": "proxy", "proxy_url": "http://egress:notaport"},
        {"language": "ruby"},
        {"unexpected": True},
        {"limits": {"memory_mb": 1}},
    ],
)
def test_unsafe_requests_are_refused(change: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        schemas.RunRequest.model_validate({"language": "python", "code": "print(1)", **change})


def test_nested_file_names_are_allowed() -> None:
    request = schemas.RunRequest(language="python", code="", files={"data/in-1.txt": "x"})
    assert list(request.files) == ["data/in-1.txt"]


# The token and body gate


def test_token_matches_only_the_exact_bearer_token(tmp_path: Path) -> None:
    s = settings(tmp_path)
    assert token_matches(f"Bearer {TOKEN}".encode(), s)
    assert token_matches(f"bearer {TOKEN}".encode(), s)
    assert not token_matches(TOKEN.encode(), s)
    assert not token_matches(f"Basic {TOKEN}".encode(), s)
    assert not token_matches(f"Bearer {TOKEN}x".encode(), s)
    assert not token_matches(b"Bearer ", s)
    assert not token_matches(b"", s)
    empty = SandboxSettings(sandbox_token="", sandbox_scratch_dir=tmp_path)
    assert not token_matches(b"Bearer ", empty)


def test_a_short_token_stops_the_service(tmp_path: Path) -> None:
    s = SandboxSettings(sandbox_token="short", sandbox_scratch_dir=tmp_path)
    assert s.problems() == ["SANDBOX_TOKEN must be set to at least 16 characters"]


async def test_startup_refuses_a_missing_token(tmp_path: Path) -> None:
    app = create_app(
        SandboxSettings(sandbox_token="", sandbox_scratch_dir=tmp_path), FakeIsolator()
    )
    with pytest.raises(RuntimeError, match="SANDBOX_TOKEN"):
        async with app.router.lifespan_context(app):
            pass


def test_without_nsjail_the_service_refuses_unless_the_fallback_is_allowed(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="nsjail not found"):
        select_isolator(settings(tmp_path))
    fallback = select_isolator(settings(tmp_path, sandbox_allow_dev_fallback=True))
    assert isinstance(fallback, DevFallbackIsolator)


@pytest.fixture
async def app_client(tmp_path: Path) -> AsyncIterator[tuple[httpx.AsyncClient, FakeIsolator]]:
    isolator = FakeIsolator()
    app = create_app(settings(tmp_path, sandbox_max_body_bytes=100_000), isolator)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://sandbox") as c:
            yield c, isolator


AUTH = {"authorization": f"Bearer {TOKEN}"}


async def test_healthz_needs_no_token(app_client: tuple[httpx.AsyncClient, FakeIsolator]) -> None:
    c, _ = app_client
    resp = await c.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["isolation"] == "fake"


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"authorization": "Bearer wrong"},
        {"authorization": TOKEN},
        {"authorization": f"Basic {TOKEN}"},
    ],
)
async def test_run_needs_the_token(
    app_client: tuple[httpx.AsyncClient, FakeIsolator], headers: dict[str, str]
) -> None:
    c, isolator = app_client
    resp = await c.post("/run", json={"language": "python", "code": "print(1)"}, headers=headers)
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "unauthorized"
    assert isolator.specs == []


async def test_a_large_body_is_refused_before_parsing(
    app_client: tuple[httpx.AsyncClient, FakeIsolator],
) -> None:
    c, isolator = app_client
    big = json.dumps({"language": "python", "code": "x", "stdin": "y" * 200_000})
    resp = await c.post("/run", content=big, headers={**AUTH, "content-type": "application/json"})
    assert resp.status_code == 413
    assert resp.json()["error"]["code"] == "body_too_large"

    async def chunks() -> AsyncIterator[bytes]:
        for _ in range(30):
            yield b" " * 10_000

    streamed = await c.post(
        "/run", content=chunks(), headers={**AUTH, "content-type": "application/json"}
    )
    assert streamed.status_code == 413
    assert isolator.specs == []


async def test_validation_errors_do_not_echo_values(
    app_client: tuple[httpx.AsyncClient, FakeIsolator],
) -> None:
    c, _ = app_client
    resp = await c.post(
        "/run",
        json={"language": "python", "code": "x", "env": {"bad name": "secret-value-123"}},
        headers=AUTH,
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "invalid_request"
    assert "secret-value-123" not in resp.text


async def test_a_run_reaches_the_backend_and_comes_back(
    app_client: tuple[httpx.AsyncClient, FakeIsolator],
) -> None:
    c, isolator = app_client
    resp = await c.post(
        "/run",
        json={
            "language": "python",
            "code": "print(42)",
            "files": {"data/x.txt": "hi"},
            "env": {"API_KEY": "k"},
            "limits": {"memory_mb": 128, "file_bytes": 2_000_000},
        },
        headers=AUTH,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"] == "ok"
    assert body["stdout"] == "42\n"
    (spec,) = isolator.specs
    assert spec.memory_mb == 128
    assert spec.env["API_KEY"] == "k"
    assert spec.scratch_mb >= 2
    # The run directory is removed afterwards.
    assert not spec.run_dir.exists()


async def test_limits_above_the_service_maximum_are_an_error_verdict(
    app_client: tuple[httpx.AsyncClient, FakeIsolator],
) -> None:
    c, isolator = app_client
    resp = await c.post(
        "/run",
        json={"language": "python", "code": "1", "limits": {"memory_mb": 4096}},
        headers=AUTH,
    )
    assert resp.status_code == 200
    assert resp.json()["verdict"] == "error"
    assert "memory_mb" in resp.json()["detail"]
    assert isolator.specs == []


async def test_a_backend_failure_is_an_error_verdict(tmp_path: Path) -> None:
    class Broken(FakeIsolator):
        def execute(self, spec: RunSpec) -> Execution:
            raise OSError("boom")

    runner = Runner(settings(tmp_path), Broken())
    runner.scratch.mkdir(parents=True)
    result = await runner.run(schemas.RunRequest(language="bash", code="true"))
    assert result.verdict == "error"
    assert list(runner.scratch.iterdir()) == []


# Environment and proxy rewrite


def test_program_env_is_the_base_plus_the_request() -> None:
    request = schemas.RunRequest(
        language="python",
        code="",
        env={"API_KEY": "k", "HTTP_PROXY": "http://evil:1", "no_proxy": "*"},
    )
    assert program_env(request) == {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": "/tmp/work",  # noqa: S108 a path inside the sandbox
        "TMPDIR": "/tmp",  # noqa: S108 a path inside the sandbox
        "LANG": "C.UTF-8",
        "API_KEY": "k",
    }


def test_proxy_mode_points_every_proxy_variable_at_the_forwarder() -> None:
    request = schemas.RunRequest(
        language="python",
        code="",
        network="proxy",
        proxy_url="http://egress:5128",
        proxy_authorization="Bearer secret",
        env={"HTTPS_PROXY": "http://evil:1"},
    )
    env = program_env(request)
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        assert env[name] == "http://127.0.0.1:3128"
    assert env["NO_PROXY"] == ""
    assert "secret" not in json.dumps(env)


def test_rewrite_strips_the_programs_credential_and_adds_the_agents() -> None:
    raw = (
        b"CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n"
        b"Proxy-Authorization: Basic Zm9yZ2Vk\r\nproxy-authorization: Bearer forged\r\n"
        b"Proxy-Connection: keep-alive\r\n\r\n"
    )
    head = rewrite_head(raw, "Bearer agent").decode()
    lines = head.split("\r\n")
    assert lines[0] == "CONNECT api.example.com:443 HTTP/1.1"
    assert [ln for ln in lines if ln.lower().startswith("proxy-authorization")] == [
        "Proxy-Authorization: Bearer agent"
    ]
    assert "Proxy-Connection: keep-alive" in lines
    assert head.endswith("\r\n\r\n")


def test_rewrite_forces_one_request_per_plain_http_connection() -> None:
    raw = b"GET http://example.com/a HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\nKeep-Alive: 5\r\n\r\n"
    lines = rewrite_head(raw, None).decode().split("\r\n")
    assert "Connection: keep-alive" not in lines
    assert "Keep-Alive: 5" not in lines
    assert "Connection: close" in lines
    assert not any(ln.lower().startswith("proxy-authorization") for ln in lines)


@pytest.mark.parametrize(
    "raw",
    [
        b"GET /internal HTTP/1.1\r\nHost: api\r\n\r\n",
        b"CONNECT nohost HTTP/1.1\r\n\r\n",
        b"CONNECT host:port HTTP/1.1\r\n\r\n",
        b"GET http://a/ HTTP/2\r\n\r\n",
        b"GET http://a/ HTTP/1.1\r\nbroken header\r\n\r\n",
        b"GET http://a/ HTTP/1.1\r\n folded: x\r\n\r\n",
        b"GET http://a/ HTTP/1.1\r\n",
    ],
)
def test_rewrite_refuses_anything_but_a_proxy_request(raw: bytes) -> None:
    with pytest.raises(BadRequestError):
        rewrite_head(raw, "Bearer agent")


# Verdicts


def verdict(language: str = "python", **kw: Any) -> tuple[str, str | None]:
    launch_failed = kw.pop("launch_failed", False)
    execution = Execution(process=supervised(**kw), launch_failed=launch_failed)
    return classify(execution, LANGUAGES[language], cpu_s=1.0, memory_mb=100)


def test_verdicts_follow_the_documented_order() -> None:
    assert verdict() == ("ok", None)
    assert verdict(launch_failed=True)[0] == "error"
    assert verdict(stopped="output", cpu_ms=5000)[0] == "output_limit"
    assert verdict(exit_code=None, signal=signal.SIGXFSZ)[0] == "output_limit"
    assert verdict(stopped="wall") == ("timeout", "wall clock limit reached")
    assert verdict(cpu_ms=1500) == ("timeout", "CPU time limit reached")
    assert verdict(exit_code=None, signal=signal.SIGXCPU)[0] == "timeout"
    assert verdict(exit_code=1, stderr=b"MemoryError\n")[0] == "memory"
    assert verdict(exit_code=None, signal=signal.SIGKILL, memory_kb=95_000)[0] == "memory"
    assert verdict("node", memory_kb=200_000)[0] == "memory"
    assert verdict(exit_code=None, signal=signal.SIGSEGV) == ("killed", "killed by SIGSEGV")
    assert verdict(exit_code=2) == ("nonzero_exit", "exit code 2")
    # A program that prints the marker but succeeds is not a memory verdict.
    assert verdict(stdout=b"", stderr=b"MemoryError")[0] == "ok"


# The nsjail command line


def spec(tmp_path: Path, *, proxy: bool) -> RunSpec:
    return RunSpec(
        language=LANGUAGES["node"],
        run_dir=tmp_path,
        env={"PATH": "/usr/bin", "API_KEY": "k"},
        cpu_s=1.5,
        wall_s=2.5,
        memory_mb=128,
        pids=8,
        output_bytes=10_000,
        file_bytes=3 << 20,
        scratch_mb=11,
        egress_dir=tmp_path / "egress" if proxy else None,
    )


def flag(cmd: list[str], name: str) -> str:
    return cmd[cmd.index(name) + 1]


def test_the_nsjail_command_carries_every_limit(tmp_path: Path) -> None:
    cmd = NsjailIsolator(read_only=("/usr",)).command(spec(tmp_path, proxy=False))
    assert flag(cmd, "--rlimit_cpu") == "3"
    assert flag(cmd, "--rlimit_as") == str(128 + 2048)
    assert flag(cmd, "--rlimit_nproc") == "8"
    assert flag(cmd, "--rlimit_fsize") == "3"
    assert flag(cmd, "--user") == "65534"
    assert "--iface_no_lo" in cmd
    assert "--disable_proc" in cmd
    assert f"none:/tmp:tmpfs:size={11 << 20}" in cmd
    assert "API_KEY=k" in cmd
    program = cmd[cmd.index("--", cmd.index("--") + 1) + 1 :]
    assert program[0] == "/usr/local/bin/node"
    assert "--max-old-space-size=128" in program
    assert program[-1] == "/tmp/work/main.js"  # noqa: S108 a path inside the sandbox


def test_proxy_mode_keeps_loopback_and_mounts_only_the_socket_directory(tmp_path: Path) -> None:
    cmd = NsjailIsolator(read_only=()).command(spec(tmp_path, proxy=True))
    assert "--iface_no_lo" not in cmd
    assert f"{tmp_path / 'egress'}:/run/egress" in cmd
    assert flag(cmd, "--rlimit_nproc") == "9"
    assert cmd[cmd.index("--proxy") : cmd.index("--proxy") + 3] == [
        "--proxy",
        "/run/egress/egress.sock",
        "3128",
    ]


# Supervision (local processes, no sandbox)


def test_supervise_caps_output_and_stops_the_flood(tmp_path: Path) -> None:
    stdin = tmp_path / "stdin"
    stdin.write_bytes(b"")
    result = supervise(
        [sys.executable, "-c", "import sys\nwhile True:\n    sys.stdout.write('x' * 1000)\n"],
        env={},
        stdin=stdin,
        cwd=tmp_path,
        wall_s=20,
        output_bytes=5000,
    )
    assert result.stopped == "output"
    assert result.stdout == b"x" * 5000
    assert result.stdout_truncated


def test_supervise_stops_at_the_wall_clock(tmp_path: Path) -> None:
    stdin = tmp_path / "stdin"
    stdin.write_bytes(b"")
    result = supervise(
        [sys.executable, "-c", "import time\ntime.sleep(30)\n"],
        env={},
        stdin=stdin,
        cwd=tmp_path,
        wall_s=0.5,
        output_bytes=5000,
    )
    assert result.stopped == "wall"
    assert result.wall_ms < 5000


def test_read_usage_parses_the_helpers_line(tmp_path: Path) -> None:
    path = tmp_path / "usage"
    path.write_text("256 120000 30000 51200\n")
    assert read_usage(path) == (256, 150, 51200)
    path.write_text("garbage")
    assert read_usage(path) is None
    assert read_usage(tmp_path / "missing") is None


async def test_the_dev_fallback_runs_and_says_it_is_not_isolated(tmp_path: Path) -> None:
    runner = Runner(settings(tmp_path, sandbox_allow_dev_fallback=True), DevFallbackIsolator())
    runner.scratch.mkdir(parents=True)
    result = await runner.run(
        schemas.RunRequest(
            language="python", code="import sys\nprint(int(sys.stdin.read()) * 2)", stdin="21"
        )
    )
    assert result.verdict == "ok", result
    assert result.stdout == "42\n"
    assert result.detail is not None and "WITHOUT isolation" in result.detail
    refused = await runner.run(
        schemas.RunRequest(language="python", code="", network="proxy", proxy_url="http://e:1")
    )
    assert refused.verdict == "error"
