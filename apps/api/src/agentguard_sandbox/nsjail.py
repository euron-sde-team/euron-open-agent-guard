"""Run one program in a fresh nsjail and measure it.

Each run gets new user, PID, network, mount, IPC, UTS and cgroup namespaces. The program
runs as uid 65534 (mapped to the service's uid outside), sees read-only system directories,
its input files read-only, a private size-limited tmpfs at ``/tmp`` and nothing else: no
``/proc``, no ``/opt`` (where the service lives), no other run. rlimits bound CPU time,
address space, processes, file size and open files; a syscall filter refuses namespace,
mount, ptrace, bpf, keyring, perf and io_uring calls inside the sandbox even though the
container's seccomp profile allows the namespace calls nsjail itself needs.

Limits come from rlimits, not cgroups: cgroups would need a privileged or cgroup-delegated
container, and the point of this design is that the container has no privileges. Since
Linux 5.14 ``RLIMIT_NPROC`` is counted per user namespace, and every run has its own, so
the process limit of one run is exact even with several runs side by side.
"""

from __future__ import annotations

import math
import os
import signal
from dataclasses import dataclass, field, replace
from pathlib import Path

from agentguard_sandbox.isolation import (
    FORWARDER_PORT,
    JAIL_EGRESS_DIR,
    JAIL_INPUT,
    JAIL_WORK,
    Execution,
    RunSpec,
)
from agentguard_sandbox.process import supervise

# System paths a program may read. Missing ones are skipped (lib64 is absent on arm64).
READ_ONLY = (
    "/usr",
    "/lib",
    "/lib64",
    "/bin",
    "/etc/alternatives",
    "/etc/ld.so.cache",
    "/etc/ssl/certs",
    "/dev/null",
    "/dev/zero",
    "/dev/random",
    "/dev/urandom",
)

# Refused inside the sandbox even though the container allows some of them (nsjail needs
# them to build the sandbox; the program never does). clone3 fails with ENOSYS so the C
# library falls back to clone, which threads still need.
POLICY = (
    "POLICY sandbox {"
    " ERRNO(38) { clone3 },"
    " ERRNO(1) { unshare, setns, mount, umount, pivot_root, chroot, ptrace, process_vm_readv,"
    " process_vm_writev, bpf, keyctl, add_key, request_key, perf_event_open, userfaultfd,"
    " io_uring_setup, io_uring_enter, io_uring_register, kexec_load, init_module,"
    " finit_module, delete_module, swapon, swapoff, reboot, acct, open_by_handle_at,"
    " name_to_handle_at, quotactl, syslog, settimeofday, clock_settime, clock_adjtime }"
    " } USE sandbox DEFAULT ALLOW"
)

OPEN_FILES = 128
STACK_MB = 8
# The service's wall clock timer stops the run; nsjail's own limit is a backstop after it.
NSJAIL_WALL_BACKSTOP_S = 2
LAUNCH_FAILED = "Couldn't launch the child process"


@dataclass
class NsjailIsolator:
    nsjail: Path = Path("/usr/local/bin/nsjail")
    measure: Path = Path("/usr/local/bin/agentguard-sandbox-measure")
    # The first process in the sandbox (native/init.c), visible there through /usr.
    init: Path = Path("/usr/local/bin/agentguard-sandbox-init")
    read_only: tuple[str, ...] = field(
        default_factory=lambda: tuple(p for p in READ_ONLY if os.path.exists(p))
    )
    name: str = "nsjail"
    supports_proxy: bool = True

    def command(self, spec: RunSpec) -> list[str]:
        language = spec.language
        address_mb = language.address_limit_mb(spec.memory_mb)
        proxy = spec.egress_dir is not None
        cmd = [
            str(self.nsjail),
            "--mode",
            "o",
            "--log",
            str(spec.run_dir / "nsjail.log"),
            "--hostname",
            "sandbox",
            "--cwd",
            "/tmp",  # noqa: S108 the sandbox tmpfs; init moves into /tmp/work
            "--user",
            "65534",
            "--group",
            "65534",
            "--max_cpus",
            "1",
            "--time_limit",
            str(math.ceil(spec.wall_s) + NSJAIL_WALL_BACKSTOP_S),
            "--rlimit_cpu",
            str(math.ceil(spec.cpu_s) + 1),
            "--rlimit_as",
            str(address_mb),
            "--rlimit_fsize",
            str(max(1, math.ceil(spec.file_bytes / (1 << 20)))),
            "--rlimit_nofile",
            str(OPEN_FILES),
            # The in-sandbox forwarder is one more process in proxy mode.
            "--rlimit_nproc",
            str(spec.pids + (1 if proxy else 0)),
            "--rlimit_stack",
            str(STACK_MB),
            "--rlimit_core",
            "0",
            "--seccomp_string",
            POLICY,
            "--mount",
            f"none:/tmp:tmpfs:size={spec.scratch_mb << 20}",
            # No /proc: Docker overmounts parts of the container's /proc, and the kernel
            # then refuses a fresh procfs inside a user namespace. Programs do not need it.
            "--disable_proc",
        ]
        if not proxy:
            # Mode none: not even a loopback interface.
            cmd.append("--iface_no_lo")
        for path in self.read_only:
            cmd += ["--bindmount_ro", path]
        cmd += ["--bindmount_ro", f"{spec.input_dir}:{JAIL_INPUT}"]
        launcher = [str(self.init), "--work", JAIL_WORK]
        if spec.egress_dir is not None:
            cmd += ["--bindmount_ro", f"{spec.egress_dir}:{JAIL_EGRESS_DIR}"]
            launcher += ["--proxy", f"{JAIL_EGRESS_DIR}/egress.sock", str(FORWARDER_PORT)]
        for name, value in spec.env.items():
            cmd += ["--env", f"{name}={value}"]
        program = language.argv(spec.memory_mb, f"{JAIL_WORK}/{language.filename}")
        return [*cmd, "--", *launcher, "--", *program]

    def execute(self, spec: RunSpec) -> Execution:
        # The helper measures nsjail and the whole sandbox (not the service's own peak
        # memory) and raises oom_score_adj, so the kernel kills the program first.
        result = supervise(
            [str(self.measure), str(spec.run_dir / "usage"), *self.command(spec)],
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
            stdin=spec.stdin_path,
            cwd=spec.run_dir,
            wall_s=spec.wall_s,
            output_bytes=spec.output_bytes,
            # Forwarded to nsjail, which ends the sandbox; the group is killed after a grace.
            stop_signal=signal.SIGTERM,
            usage_file=spec.run_dir / "usage",
        )
        log_path = spec.run_dir / "nsjail.log"
        log = log_path.read_text(errors="replace")[-4000:] if log_path.exists() else ""
        launch_failed = result.exit_code == 255 and LAUNCH_FAILED in log
        # nsjail reports a child killed by a signal as 128 + signal; recover the signal.
        code = result.exit_code
        if not launch_failed and code is not None and 128 < code <= 128 + 64 and "signal" in log:
            result = replace(result, exit_code=None, signal=code - 128)
        return Execution(
            process=result,
            launch_failed=launch_failed,
            detail="nsjail could not start the program" if launch_failed else None,
        )
