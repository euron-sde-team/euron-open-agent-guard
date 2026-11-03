"""One run end to end: refuse, prepare, relay, execute, classify, clean up.

The runner owns the per-run directory under ``SANDBOX_SCRATCH_DIR`` (input files, stdin,
the nsjail log and, in proxy mode, the relay's unix socket) and removes it whatever
happens. At most ``SANDBOX_CONCURRENCY`` runs execute at once; the rest wait their turn.
"""

from __future__ import annotations

import asyncio
import logging
import math
import shutil
import time
import uuid
from pathlib import Path

from agentguard_sandbox.config import SandboxSettings
from agentguard_sandbox.isolation import FORWARDER_PORT, JAIL_WORK, Execution, Isolator, RunSpec
from agentguard_sandbox.languages import LANGUAGES
from agentguard_sandbox.relay import EgressRelay
from agentguard_sandbox.schemas import RunRequest, RunResult
from agentguard_sandbox.verdict import classify

log = logging.getLogger("agentguard_sandbox.run")

BASE_ENV = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "HOME": JAIL_WORK,
    "TMPDIR": "/tmp",  # noqa: S108 the sandbox's private tmpfs
    "LANG": "C.UTF-8",
}
PROXY_ENV_NAMES = ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")
# Room in the scratch tmpfs beyond the largest file a program may write.
SCRATCH_SLACK_MB = 8


def program_env(request: RunRequest) -> dict[str, str]:
    """The program's whole environment: base, the request's, then the proxy settings.

    Nothing of the service's own environment is included (nsjail clears it), so neither
    ``SANDBOX_TOKEN`` nor anything else of the service reaches the program.
    """
    env = {**BASE_ENV, **request.env}
    for name in (*PROXY_ENV_NAMES, "NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy"):
        env.pop(name, None)
    if request.network == "proxy":
        for name in PROXY_ENV_NAMES:
            env[name] = f"http://127.0.0.1:{FORWARDER_PORT}"
        env["NO_PROXY"] = ""
        env["no_proxy"] = ""
        # Node 22 honours the proxy variables in fetch only when asked to.
        env["NODE_USE_ENV_PROXY"] = "1"
    return env


class Runner:
    def __init__(self, settings: SandboxSettings, isolator: Isolator) -> None:
        self.settings = settings
        self.isolator = isolator
        self.scratch = settings.sandbox_scratch_dir
        self._slots = asyncio.Semaphore(settings.sandbox_concurrency)

    def refusal(self, request: RunRequest) -> str | None:
        """Why this service will not run ``request``, or ``None``."""
        s, limits = self.settings, request.limits
        if limits.memory_mb > s.sandbox_max_memory_mb:
            return f"memory_mb is above this sandbox's maximum of {s.sandbox_max_memory_mb}"
        if limits.pids > s.sandbox_max_pids:
            return f"pids is above this sandbox's maximum of {s.sandbox_max_pids}"
        if limits.file_bytes > s.sandbox_max_file_mb << 20:
            return f"file_bytes is above this sandbox's maximum of {s.sandbox_max_file_mb} MB"
        if request.network == "proxy" and not self.isolator.supports_proxy:
            return f"network=proxy is not available with the {self.isolator.name} backend"
        return None

    async def run(self, request: RunRequest) -> RunResult:
        run_id = uuid.uuid4().hex
        reason = self.refusal(request)
        if reason is not None:
            self._log(run_id, request, "error", None, reason)
            return RunResult(verdict="error", detail=reason)
        async with self._slots:
            started = time.monotonic()
            run_dir = self.scratch / run_id
            relay: EgressRelay | None = None
            try:
                spec = await asyncio.to_thread(self._prepare, run_dir, request)
                if spec.egress_dir is not None:
                    relay = EgressRelay(
                        spec.egress_dir / "egress.sock",
                        request.proxy_address(),
                        request.proxy_authorization,
                    )
                    await relay.start()
                execution = await asyncio.to_thread(self.isolator.execute, spec)
            except Exception:
                log.exception("run failed", extra={"run_id": run_id})
                return RunResult(
                    verdict="error",
                    wall_ms=round((time.monotonic() - started) * 1000),
                    detail="the sandbox service failed to run the program",
                )
            finally:
                if relay is not None:
                    await relay.close()
                await asyncio.to_thread(shutil.rmtree, run_dir, True)
            result = self._result(execution, request)
            self._log(run_id, request, result.verdict, result, None, relay)
            return result

    def _prepare(self, run_dir: Path, request: RunRequest) -> RunSpec:
        language = LANGUAGES[request.language]
        inputs = run_dir / "in"
        inputs.mkdir(parents=True, mode=0o700)
        run_dir.chmod(0o700)
        (inputs / language.filename).write_text(request.code, encoding="utf-8")
        size = len(request.code.encode())
        for name, content in request.files.items():
            target = inputs / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            size += len(content.encode())
        (run_dir / "stdin").write_text(request.stdin, encoding="utf-8")
        egress: Path | None = None
        if request.network == "proxy":
            egress = run_dir / "egress"
            egress.mkdir(mode=0o700)
        limits = request.limits
        scratch_mb = math.ceil((limits.file_bytes + size) / (1 << 20)) + SCRATCH_SLACK_MB
        return RunSpec(
            language=language,
            run_dir=run_dir,
            env=program_env(request),
            cpu_s=limits.cpu_s,
            wall_s=limits.wall_s,
            memory_mb=limits.memory_mb,
            pids=limits.pids,
            output_bytes=limits.output_bytes,
            file_bytes=limits.file_bytes,
            scratch_mb=scratch_mb,
            egress_dir=egress,
        )

    def _result(self, execution: Execution, request: RunRequest) -> RunResult:
        language = LANGUAGES[request.language]
        verdict, detail = classify(
            execution, language, cpu_s=request.limits.cpu_s, memory_mb=request.limits.memory_mb
        )
        if execution.detail and not execution.launch_failed:
            detail = f"{detail}; {execution.detail}" if detail else execution.detail
        p = execution.process
        return RunResult(
            verdict=verdict,
            exit_code=p.exit_code,
            signal=p.signal,
            stdout=p.stdout.decode("utf-8", errors="replace"),
            stderr=p.stderr.decode("utf-8", errors="replace"),
            stdout_truncated=p.stdout_truncated,
            stderr_truncated=p.stderr_truncated,
            cpu_ms=p.cpu_ms,
            wall_ms=p.wall_ms,
            memory_kb=p.memory_kb,
            detail=detail,
        )

    def _log(
        self,
        run_id: str,
        request: RunRequest,
        verdict: str,
        result: RunResult | None,
        refused: str | None,
        relay: EgressRelay | None = None,
    ) -> None:
        # Sizes and counts only: never the code, stdin, file contents or env values.
        fields: dict[str, object] = {
            "run_id": run_id,
            "language": request.language,
            "network": request.network,
            "verdict": verdict,
            "code_bytes": len(request.code.encode()),
            "files": len(request.files),
            "env_vars": len(request.env),
            "backend": self.isolator.name,
        }
        if refused is not None:
            fields["refused"] = refused
        if result is not None:
            fields.update(
                exit_code=result.exit_code,
                signal=result.signal,
                cpu_ms=result.cpu_ms,
                wall_ms=result.wall_ms,
                memory_kb=result.memory_kb,
                stdout_bytes=len(result.stdout),
                stderr_bytes=len(result.stderr),
            )
        if relay is not None:
            fields.update(
                egress_connections=relay.connections,
                egress_bytes_up=relay.bytes_up,
                egress_bytes_down=relay.bytes_down,
            )
        log.info("run finished", extra={"fields": fields})
