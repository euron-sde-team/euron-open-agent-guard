"""The isolation backend interface: how one prepared run is executed.

The runner prepares a run directory and a :class:`RunSpec`; a backend executes it and
returns an :class:`Execution`. Today there are two backends: nsjail (the only one used in
the image) and an explicitly opted-in development fallback with no isolation. A stronger
kernel boundary (gVisor ``runsc``, Firecracker) would be a third implementation of
:class:`Isolator`, chosen by configuration, with no change to the runner or the API.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from agentguard_sandbox.languages import Language
from agentguard_sandbox.process import Supervised

# Where things appear inside the sandbox.
JAIL_INPUT = "/sandbox/in"
JAIL_EGRESS_DIR = "/run/egress"
JAIL_WORK = "/tmp/work"  # noqa: S108 inside the sandbox's private tmpfs
FORWARDER_PORT = 3128


@dataclass(frozen=True, slots=True)
class RunSpec:
    """Everything a backend needs for one run, already validated and bounded."""

    language: Language
    # Holds in/ (code and files), stdin, and egress/ in proxy mode.
    run_dir: Path
    env: dict[str, str]
    cpu_s: float
    wall_s: float
    memory_mb: int
    pids: int
    output_bytes: int
    file_bytes: int
    # Size of the private scratch tmpfs.
    scratch_mb: int
    # proxy mode: the directory holding the relay's unix socket (mounted read-only).
    egress_dir: Path | None = None

    @property
    def input_dir(self) -> Path:
        return self.run_dir / "in"

    @property
    def stdin_path(self) -> Path:
        return self.run_dir / "stdin"


@dataclass(frozen=True, slots=True)
class Execution:
    process: Supervised
    # The backend could not start the program (its own failure, not the program's).
    launch_failed: bool = False
    detail: str | None = None


class Isolator(Protocol):
    """One way of running a :class:`RunSpec` in isolation."""

    name: str
    # Whether network=proxy is supported (it needs a network namespace).
    supports_proxy: bool

    def execute(self, spec: RunSpec) -> Execution:
        """Run the program to completion. Blocking; the runner calls it in a thread."""
        ...
