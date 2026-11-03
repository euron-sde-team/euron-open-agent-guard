"""Normal runs: every language, stdin, files, environment, measurement and verdicts."""

from __future__ import annotations

import pytest

from agentguard_sandbox.runner import Runner
from tests.sandbox.conftest import assert_healthy, run


async def test_every_language_answers_correctly(runner: Runner) -> None:
    await assert_healthy(runner)


async def test_files_are_in_a_writable_scratch_directory(runner: Runner) -> None:
    code = (
        "import os\n"
        "print(os.getcwd(), os.environ['HOME'])\n"
        "print(open('data/in.txt').read().strip())\n"
        "open('data/in.txt', 'a').write('more')\n"
        "open('new.txt', 'w').write('x' * 1000)\n"
        "print(sorted(os.listdir('.')), os.path.getsize('new.txt'))\n"
    )
    result = await run(runner, "python", code, files={"data/in.txt": "hello"})
    assert result.verdict == "ok", result
    lines = result.stdout.splitlines()
    assert lines[0] == "/tmp/work /tmp/work"  # noqa: S108 a path inside the sandbox
    assert lines[1] == "hello"
    assert lines[2] == "['data', 'main.py', 'new.txt'] 1000"


async def test_the_environment_is_only_the_request_and_a_minimal_base(runner: Runner) -> None:
    code = "import os, json\nprint(json.dumps(dict(os.environ), sort_keys=True))\n"
    result = await run(runner, "python", code, env={"API_KEY": "injected-secret"})
    assert result.verdict == "ok", result
    import json

    env = json.loads(result.stdout)
    assert env == {
        "API_KEY": "injected-secret",
        "HOME": "/tmp/work",  # noqa: S108 a path inside the sandbox
        "LANG": "C.UTF-8",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "TMPDIR": "/tmp",  # noqa: S108 a path inside the sandbox
    }


async def test_nonzero_exit_and_stderr_are_reported(runner: Runner) -> None:
    result = await run(runner, "bash", "echo oops >&2\nexit 3\n")
    assert result.verdict == "nonzero_exit"
    assert result.exit_code == 3
    assert result.stderr == "oops\n"


async def test_a_crash_is_reported_as_killed(runner: Runner) -> None:
    result = await run(runner, "python", "import ctypes\nctypes.string_at(0)\n")
    assert result.verdict == "killed", result
    assert result.signal == 11
    assert result.detail == "killed by SIGSEGV"


async def test_cpu_time_is_measured_not_wall_time(runner: Runner) -> None:
    sleeper = await run(runner, "python", "import time\ntime.sleep(1)\n")
    assert sleeper.verdict == "ok"
    assert sleeper.wall_ms >= 1000
    assert sleeper.cpu_ms < 300, sleeper
    spinner = await run(runner, "python", "n = 0\nfor i in range(10_000_000):\n    n += i\n")
    assert spinner.verdict == "ok"
    assert spinner.cpu_ms > 200, spinner


async def test_peak_memory_is_measured_exactly(runner: Runner) -> None:
    small = await run(runner, "bash", "true\n")
    assert small.memory_kb < 20_000, small
    big = await run(
        runner,
        "python",
        "b = bytearray(100 * 1024 * 1024)\nfor i in range(0, len(b), 4096):\n    b[i] = 1\n",
        limits={"memory_mb": 256},
    )
    assert big.verdict == "ok", big
    assert 100_000 <= big.memory_kb <= 130_000, big


@pytest.mark.parametrize(
    ("language", "code"),
    [
        ("node", "console.log(JSON.stringify({ok: [1, 2, 3].map(x => x * 2)}))"),
        ("bash", "for i in 1 2 3; do echo -n $i; done; echo"),
    ],
)
async def test_other_languages(runner: Runner, language: str, code: str) -> None:
    result = await run(runner, language, code)
    assert result.verdict == "ok", result
    assert result.stdout.strip() in ('{"ok":[2,4,6]}', "123")
