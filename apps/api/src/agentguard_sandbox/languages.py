"""How each language is started and how its memory is bounded.

Two memory modes, as in CodeJudge:

- ``address``: ``RLIMIT_AS`` is the limit plus the interpreter's own overhead, so an
  allocation past it fails at once (``MemoryError`` in Python, ``xmalloc`` in bash).
- ``rss``: runtimes that reserve far more address space than they use (V8 reserves
  gigabytes at start) cannot run under an address limit near their real use. Node gets
  its own heap flag, a generous address ceiling that still stops runaway off-heap
  allocations, and its peak resident memory is checked after the run.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

MemoryMode = Literal["address", "rss"]


@dataclass(frozen=True, slots=True)
class Language:
    name: str
    # File the code is written to, in the scratch directory.
    filename: str
    # Absolute path of the interpreter inside the sandbox image.
    interpreter: str
    memory_mode: MemoryMode
    # Added to the limit for RLIMIT_AS (address mode) or allowed above it (rss mode).
    overhead_mb: int
    # stderr text that means the program ran out of memory.
    memory_markers: tuple[str, ...]

    def argv(self, memory_mb: int, path: str) -> list[str]:
        """The command that runs the code file at ``path`` under ``memory_mb``."""
        if self.name == "node":
            # Explicit WebAssembly bounds checks instead of guard regions: otherwise every
            # Wasm memory (fetch uses one) reserves about 10 GB of address space.
            return [
                self.interpreter,
                f"--max-old-space-size={memory_mb}",
                "--disable-wasm-trap-handler",
                path,
            ]
        if self.name == "python":
            return [self.interpreter, "-u", path]
        return [self.interpreter, path]

    def address_limit_mb(self, memory_mb: int) -> int:
        """``RLIMIT_AS`` in MB for a run limited to ``memory_mb``."""
        if self.memory_mode == "address":
            return memory_mb + self.overhead_mb
        # V8 reserves its code range and heap up front; this ceiling allows for that but
        # still stops a program from allocating without bound off the heap.
        return memory_mb + NODE_RESERVE_MB


# Address space V8 needs beyond its heap: Node 22 starts with about 1 GB on arm64 (measured
# with 8 MB stacks and a busy thread pool); doubled for margin across architectures.
NODE_RESERVE_MB = 2048

LANGUAGES: dict[str, Language] = {
    "python": Language(
        name="python",
        filename="main.py",
        interpreter="/usr/local/bin/python3",
        memory_mode="address",
        overhead_mb=64,
        memory_markers=("MemoryError",),
    ),
    "node": Language(
        name="node",
        filename="main.js",
        interpreter="/usr/local/bin/node",
        memory_mode="rss",
        overhead_mb=64,
        memory_markers=(
            "heap out of memory",
            "Array buffer allocation failed",
            "RangeError: Invalid typed array length",
            "Cannot allocate memory",
        ),
    ),
    "bash": Language(
        name="bash",
        filename="main.sh",
        interpreter="/bin/bash",
        memory_mode="address",
        overhead_mb=64,
        memory_markers=("xmalloc", "Cannot allocate memory", "cannot allocate memory"),
    ),
}
