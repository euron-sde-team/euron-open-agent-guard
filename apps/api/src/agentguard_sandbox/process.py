"""Supervise one child process: output caps, a wall clock and exact measurement.

The child's stdout and stderr are pipes read by two threads that keep at most the output
limit of each and stop the run the moment either goes past it, so a flood costs neither
disk nor memory. A timer stops the run at the wall clock limit. The child is reaped with
``wait4``, whose ``rusage`` covers every descendant the child reaped: for nsjail that is
the whole sandbox, so CPU time and peak memory are exact.
"""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Literal

StopReason = Literal["wall", "output"]
CHUNK = 65_536
# After the polite stop signal, the whole process group is killed this much later.
KILL_GRACE_S = 2.0


@dataclass(slots=True)
class Stream:
    """What one pipe produced, capped at ``limit`` bytes."""

    limit: int
    data: bytearray = field(default_factory=bytearray)
    total: int = 0

    @property
    def truncated(self) -> bool:
        return self.total > self.limit


@dataclass(frozen=True, slots=True)
class Supervised:
    exit_code: int | None
    signal: int | None
    cpu_ms: int
    wall_ms: int
    memory_kb: int
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    stderr_truncated: bool
    stopped: StopReason | None


class _Stopper:
    """Stops the child once, for the first reason, then kills its group after a grace."""

    def __init__(self, pid: int, stop_signal: signal.Signals) -> None:
        self.pid = pid
        self.stop_signal = stop_signal
        self.reason: StopReason | None = None
        self._lock = threading.Lock()
        self._kill_timer: threading.Timer | None = None

    def stop(self, reason: StopReason) -> None:
        with self._lock:
            if self.reason is not None:
                return
            self.reason = reason
            with contextlib.suppress(ProcessLookupError):
                os.kill(self.pid, self.stop_signal)
            self._kill_timer = threading.Timer(KILL_GRACE_S, self.kill_group)
            self._kill_timer.daemon = True
            self._kill_timer.start()

    def kill_group(self) -> None:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(self.pid, signal.SIGKILL)

    def cancel(self) -> None:
        with self._lock:
            if self._kill_timer is not None:
                self._kill_timer.cancel()


def _drain(pipe: IO[bytes], stream: Stream, stopper: _Stopper) -> None:
    fd = pipe.fileno()
    while True:
        try:
            chunk = os.read(fd, CHUNK)
        except OSError:
            break
        if not chunk:
            break
        room = stream.limit - len(stream.data)
        if room > 0:
            stream.data += chunk[:room]
        stream.total += len(chunk)
        if stream.truncated:
            # Keep reading (and discarding) so the child never blocks on a full pipe.
            stopper.stop("output")
    pipe.close()


def supervise(
    argv: list[str],
    *,
    env: dict[str, str],
    stdin: Path,
    cwd: Path | None,
    wall_s: float,
    output_bytes: int,
    stop_signal: signal.Signals = signal.SIGKILL,
    preexec_fn: Callable[[], None] | None = None,
    usage_file: Path | None = None,
) -> Supervised:
    """Run ``argv`` to completion under the wall clock and output limits.

    With ``usage_file``, ``argv`` is the measuring helper (``native/measure.c``), and the
    status, CPU time and peak memory it recorded for its command replace the ones of the
    helper itself, which carry the service's own peak memory.
    """
    started = time.monotonic()
    with stdin.open("rb") as fin:
        proc = subprocess.Popen(  # noqa: S603 fixed argv built by the service, no shell
            argv,
            stdin=fin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=cwd,
            start_new_session=True,
            close_fds=True,
            preexec_fn=preexec_fn,
        )
    stopper = _Stopper(proc.pid, stop_signal)
    assert proc.stdout is not None
    assert proc.stderr is not None
    out, err = Stream(output_bytes), Stream(output_bytes)
    readers = [
        threading.Thread(target=_drain, args=(proc.stdout, out, stopper), daemon=True),
        threading.Thread(target=_drain, args=(proc.stderr, err, stopper), daemon=True),
    ]
    for reader in readers:
        reader.start()
    wall = threading.Timer(wall_s, stopper.stop, ("wall",))
    wall.daemon = True
    wall.start()
    try:
        _, status, usage = os.wait4(proc.pid, 0)
    finally:
        wall.cancel()
        proc.returncode = 0  # reaped by wait4 above; stop Popen from waiting again
    wall_ms = round((time.monotonic() - started) * 1000)
    # Anything still holding the pipes (a stray grandchild) dies with the group.
    stopper.kill_group()
    for reader in readers:
        reader.join(timeout=5)
    stopper.cancel()
    cpu_ms = round((usage.ru_utime + usage.ru_stime) * 1000)
    memory_kb = _maxrss_kb(usage.ru_maxrss)
    measured = read_usage(usage_file) if usage_file is not None else None
    if measured is not None:
        status, cpu_ms, memory_kb = measured
    exit_code, sig = decode_status(status)
    return Supervised(
        exit_code=exit_code,
        signal=sig,
        cpu_ms=cpu_ms,
        wall_ms=wall_ms,
        memory_kb=memory_kb,
        stdout=bytes(out.data),
        stderr=bytes(err.data),
        stdout_truncated=out.truncated,
        stderr_truncated=err.truncated,
        stopped=stopper.reason,
    )


def read_usage(path: Path) -> tuple[int, int, int] | None:
    """``(wait status, cpu ms, peak kb)`` from the measuring helper, if it wrote them."""
    try:
        status, user_us, sys_us, maxrss = path.read_text().split()
        return int(status), round((int(user_us) + int(sys_us)) / 1000), int(maxrss)
    except (OSError, ValueError):
        return None


def decode_status(status: int) -> tuple[int | None, int | None]:
    if os.WIFSIGNALED(status):
        return None, os.WTERMSIG(status)
    return os.WEXITSTATUS(status), None


def _maxrss_kb(value: int) -> int:
    # Linux reports kilobytes, macOS (the dev fallback) bytes.
    return value // 1024 if os.uname().sysname == "Darwin" else value
