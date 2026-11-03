"""Development fallback: run the program directly, with NO isolation.

Only for working on the service itself on a machine without nsjail (macOS, for example),
and only when ``SANDBOX_ALLOW_DEV_FALLBACK=true``. The program runs as the service's own
user with the service's file system and network; only the environment, the wall clock,
the output caps and best-effort rlimits apply. ``/healthz`` reports the backend so this
can never be mistaken for the real sandbox, and every result says so in ``detail``.
Network mode ``proxy`` is refused: without a network namespace it would mean nothing.
"""

from __future__ import annotations

import contextlib
import math
import resource
import shutil
from dataclasses import dataclass

from agentguard_sandbox.isolation import Execution, RunSpec
from agentguard_sandbox.process import supervise

DETAIL = "dev fallback: the program ran WITHOUT isolation (no nsjail)"


@dataclass
class DevFallbackIsolator:
    name: str = "dev-fallback"
    supports_proxy: bool = False

    def execute(self, spec: RunSpec) -> Execution:
        work = spec.run_dir / "work"
        shutil.copytree(spec.input_dir, work)
        interpreter = shutil.which(spec.language.interpreter.rsplit("/", 1)[-1])
        if interpreter is None:
            interpreter = spec.language.interpreter
        argv = spec.language.argv(spec.memory_mb, str(work / spec.language.filename))
        argv[0] = interpreter
        env = {**spec.env, "HOME": str(work), "TMPDIR": str(work)}

        def limits() -> None:
            cpu = math.ceil(spec.cpu_s) + 1
            for which, value in (
                (resource.RLIMIT_CPU, cpu),
                (resource.RLIMIT_FSIZE, spec.file_bytes),
                (resource.RLIMIT_CORE, 0),
            ):
                with contextlib.suppress(ValueError, OSError):
                    resource.setrlimit(which, (value, value))

        result = supervise(
            argv,
            env=env,
            stdin=spec.stdin_path,
            cwd=work,
            wall_s=spec.wall_s,
            output_bytes=spec.output_bytes,
            preexec_fn=limits,
        )
        return Execution(process=result, detail=DETAIL)
