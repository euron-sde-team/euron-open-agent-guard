"""Decide a run's verdict from what was measured, in a fixed order.

1. ``error`` when the backend could not start the program (the service's failure).
2. ``output_limit`` when stdout or stderr passed the cap, or the program got ``SIGXFSZ``
   (a file write past ``file_bytes``). Before the time limit on purpose: a program cut off
   mid-print may then spin until it is stopped, and the output is the real cause.
3. ``timeout`` when the wall clock ran out, the measured CPU time passed the limit, or the
   program got ``SIGXCPU``.
4. ``memory`` when the program says it ran out, when an rss-mode runtime's peak passed
   the limit, or when it died abnormally at 90% of the limit or more.
5. ``killed`` for any other signal, ``nonzero_exit`` for a non-zero exit, else ``ok``.
"""

from __future__ import annotations

import signal

from agentguard_sandbox.isolation import Execution
from agentguard_sandbox.languages import Language

NEAR_LIMIT = 0.9


def classify(
    execution: Execution, language: Language, *, cpu_s: float, memory_mb: int
) -> tuple[str, str | None]:
    """The verdict and a short human explanation (or ``None`` for ``ok``)."""
    p = execution.process
    if execution.launch_failed:
        return "error", execution.detail or "the sandbox could not start the program"
    if p.stopped == "output" or p.signal == signal.SIGXFSZ:
        if p.signal == signal.SIGXFSZ and p.stopped != "output":
            return "output_limit", "a file write passed file_bytes"
        return "output_limit", "output passed output_bytes"
    if p.stopped == "wall":
        return "timeout", "wall clock limit reached"
    if p.signal == signal.SIGXCPU or p.cpu_ms > cpu_s * 1000:
        return "timeout", "CPU time limit reached"
    limit_kb = memory_mb * 1024
    stderr = p.stderr.decode("utf-8", errors="replace")
    abnormal = p.signal is not None or (p.exit_code or 0) != 0
    if abnormal and any(marker in stderr for marker in language.memory_markers):
        return "memory", "the program ran out of memory"
    if language.memory_mode == "rss" and p.memory_kb > limit_kb + language.overhead_mb * 1024:
        return "memory", "peak resident memory passed memory_mb"
    if abnormal and p.memory_kb >= NEAR_LIMIT * limit_kb:
        return "memory", "the program died at its memory limit"
    if p.signal is not None:
        name = signal.Signals(p.signal).name if p.signal in iter_signals() else str(p.signal)
        return "killed", f"killed by {name}"
    if p.exit_code not in (0, None):
        return "nonzero_exit", f"exit code {p.exit_code}"
    return "ok", None


def iter_signals() -> set[int]:
    return {int(s) for s in signal.Signals}
