# The sandbox

Agents ask AgentGuard to run code: a data transformation in Python, a script in Node.js, a
shell pipeline. That code is untrusted by assumption. It may have been written by a
prompt-injected model, it may try to read the credentials AgentGuard injects for it, reach
the API, the database or the cloud's metadata service, or simply loop forever or fork until
the machine stops. The sandbox has four jobs:

1. **Contain**: nothing a program does reaches the sandbox service, other runs, the
   network or the host.
2. **Limit**: CPU time, memory, processes, output, file size and wall clock are bounded
   per run.
3. **Measure**: CPU time and peak memory are measured exactly, so verdicts and limits are
   decided from facts.
4. **Survive**: after any of the above, the next run is executed correctly.

The API and the worker never execute submitted code. They post it to the sandbox service
(`apps/api/src/agentguard_sandbox`, its own image `infra/docker/sandbox.Dockerfile`)
through `agentguard.sandbox.client`. The design is the one proven in Euron Open
CodeJudge: an unprivileged container, nsjail per run built from user namespaces, rlimits
instead of cgroups.

## The service

| Endpoint | Purpose |
| --- | --- |
| `GET /healthz` | Liveness, and which isolation backend is active (`nsjail`, or `dev-fallback`) |
| `POST /run` | One run: `RunRequest` in, `RunResult` out (the contract in `agentguard/sandbox/client.py`) |

Every request except `/healthz` must carry `Authorization: Bearer <SANDBOX_TOKEN>`. The
token is compared in constant time by an ASGI gate that runs before FastAPI reads the
body, and bodies above `SANDBOX_MAX_BODY_BYTES` (8 MB) are refused with 413 by their
declared length, or cut off when they stream past it. Validation errors name the field
and the problem but never echo the submitted value. The service refuses to start when the
token is shorter than 16 characters, or when nsjail is missing and the development
fallback is not explicitly allowed.

At most `SANDBOX_CONCURRENCY` runs (default 4) execute at once; the rest wait their turn.
The service also caps what one run may ask for (`SANDBOX_MAX_MEMORY_MB` 1024,
`SANDBOX_MAX_PIDS` 256, `SANDBOX_MAX_FILE_MB` 256): a request above them gets verdict
`error` with the reason, so one caller cannot reserve more than its share of the
container. Logs are JSON lines with the run id, language, network mode, verdict, exit
code, measurements and sizes; never the code, stdin, file contents, environment values or
the token.

| Setting | Default | Meaning |
| --- | --- | --- |
| `SANDBOX_TOKEN` | (required) | Shared with the API; at least 16 characters |
| `SANDBOX_CONCURRENCY` | 4 | Runs executing at once |
| `SANDBOX_SCRATCH_DIR` | `/tmp/agentguard-sandbox` | Per-run directories, on the container's tmpfs |
| `NSJAIL_PATH` | `/usr/local/bin/nsjail` | The nsjail binary |
| `SANDBOX_ALLOW_DEV_FALLBACK` | false | Development only: run without isolation when nsjail is absent |
| `SANDBOX_MAX_MEMORY_MB`, `SANDBOX_MAX_PIDS`, `SANDBOX_MAX_FILE_MB` | 1024, 256, 256 | Largest limits one run may ask for |
| `SANDBOX_MAX_BODY_BYTES` | 8000000 | Largest request body |
| `SANDBOX_HOST`, `SANDBOX_PORT` | `0.0.0.0`, 8080 in the image | Listen address |

## Layer 1: the container

| Control | Setting | Why |
| --- | --- | --- |
| Capabilities | `cap_drop: ALL` | Nothing to abuse: no `CAP_SYS_ADMIN`, no `CAP_NET_RAW` |
| `no-new-privileges` | on | No setuid binary can raise privileges |
| Seccomp | Docker's default profile plus `clone, unshare, mount, umount2, pivot_root, sethostname, setdomainname, setns` (`infra/docker/sandbox-seccomp.json`) | Docker's default blocks namespace creation unless `CAP_SYS_ADMIN` is held. Allowing these calls without the capability is what lets nsjail build a sandbox while the container stays unprivileged; the kernel still allows them only inside a new user namespace |
| Root filesystem | read-only | The service cannot be modified, even by itself |
| Scratch | tmpfs `/tmp` (exec, 1 GB, mode 0700) owned by uid 10001 | Per-run directories and the relay sockets |
| User | uid 10001 | Never root |
| Limits | `pids_limit: 512`, `mem_limit: 3g`, `cpus: 2` | The outer bound on everything below; size them for `SANDBOX_CONCURRENCY` times the largest run |
| Network | An internal network shared only with the API and the egress proxy | The service needs no internet; sandboxed code has no network of its own at all (below) |
| Secrets | `SANDBOX_TOKEN` only | A compromised service can run code, nothing else |

The image carries only FastAPI, uvicorn and pydantic (the `sandbox` dependency group of
`uv.lock`), nsjail built from the pinned 3.6 release, two small static helpers, Python
3.12, the Node.js 22 binary (no npm) and bash. None of the API's code, libraries or
configuration is in it.

## Layer 2: nsjail, one sandbox per run

| Namespace or control | Effect |
| --- | --- |
| User namespace | The program runs as uid 65534, mapped to the service's uid 10001 outside. It holds no capability that means anything outside the namespace |
| PID namespace | It sees only its own processes; `kill -9 -1` kills only them. The program is PID 1, so when it exits the kernel ends everything else in the sandbox |
| Network namespace | Mode `none`: no interface is up, not even loopback. Mode `proxy`: loopback only (see below) |
| Mount namespace | Read-only `/usr`, `/lib`, `/bin` (and `/lib64` where it exists), `/etc/alternatives`, `/etc/ld.so.cache`, `/etc/ssl/certs`, `/dev/null`, `/dev/zero`, `/dev/random`, `/dev/urandom`; the run's input read-only at `/sandbox/in`; a private tmpfs at `/tmp` sized to `file_bytes` plus the input plus 8 MB. Nothing else exists: no `/etc/passwd` or `/etc/shadow`, no `/opt` (where the service lives), no `/proc`, no `/sys`, no other run |
| IPC, UTS, cgroup | Private; hostname `sandbox` |
| Environment | Only `PATH=/usr/local/bin:/usr/bin:/bin`, `HOME=/tmp/work`, `TMPDIR=/tmp`, `LANG=C.UTF-8`, the request's `env`, and the proxy variables in proxy mode. nsjail starts from an empty environment, so nothing of the service (no `SANDBOX_TOKEN`) reaches the program |
| CPU | `--max_cpus 1`: a multi-threaded or forking program uses at most one core |

The first process inside is `agentguard-sandbox-init` (`native/init.c`, static). It copies
the input (the code and the request's `files`) into `/tmp/work`, the writable scratch
directory, starts the proxy forwarder in proxy mode, and replaces itself with the
interpreter. It is a small static binary rather than a script because Linux carries a
process's peak memory across `exec`: a Python launcher would have added its own 15 MB to
every run's measured memory.

### The syscall filter on the program

The container's seccomp profile has to allow namespace calls so nsjail can build the
sandbox; the program never needs them. A second filter (kafel, applied by nsjail just
before `exec`) makes them fail inside:

- `EPERM` for `unshare`, `setns`, `mount`, `umount`, `pivot_root`, `chroot`, `ptrace`,
  `process_vm_readv`, `process_vm_writev`, `bpf`, `keyctl`, `add_key`, `request_key`,
  `perf_event_open`, `userfaultfd`, the `io_uring` calls, module loading, `kexec_load`,
  `swapon` and `swapoff`, `reboot`, `acct`, `open_by_handle_at`, `name_to_handle_at`,
  `quotactl`, `syslog`, and setting the clock.
- `ENOSYS` for `clone3`, so the C library falls back to `clone`, which threads still need.

### Limits: rlimits, a wall clock and output caps

| Limit | How | Catches |
| --- | --- | --- |
| CPU time (`cpu_s`) | `RLIMIT_CPU` of `cpu_s` rounded up plus 1 s, and the verdict from the measured total | Infinite loops |
| Memory (`memory_mb`) | `RLIMIT_AS` of the limit plus 64 MB for Python and bash. Node gets `--max-old-space-size` of the limit, `--disable-wasm-trap-handler` (otherwise every WebAssembly memory, and `fetch` uses one, reserves about 10 GB of address space) and `RLIMIT_AS` of the limit plus 2 GB for what V8 reserves; its peak resident memory is also checked after the run | Memory bombs fail to allocate (`MemoryError`, `heap out of memory`, `Array buffer allocation failed`, bash `xmalloc`) |
| Processes and threads (`pids`) | `RLIMIT_NPROC`, plus one for the forwarder in proxy mode | Fork and thread bombs stop at the limit |
| File size (`file_bytes`) | `RLIMIT_FSIZE`, and the scratch tmpfs size | Files that grow without bound (`EFBIG`, `SIGXFSZ`); filling scratch with many files (`ENOSPC`) |
| Output (`output_bytes`) | stdout and stderr are pipes read by the service, which keeps at most the limit of each and stops the run the moment either passes it | Output floods cost neither disk nor memory |
| Wall clock (`wall_s`) | A timer in the service stops the run exactly at the limit; nsjail's own `--time_limit` two seconds later and a process group kill are backstops | Programs that sleep or block on input |
| Open files | `RLIMIT_NOFILE` 128 | Descriptor exhaustion |
| Stack, core | `RLIMIT_STACK` 8 MB, `RLIMIT_CORE` 0 | Thread stacks stay small under the address limit; no core files |

cgroups would give a stricter memory ceiling, but they need a privileged or
cgroup-delegated container, which is exactly what this design avoids. The usual weakness
of rlimits is that `RLIMIT_NPROC` counts per user, and every sandbox maps to the same uid
outside. Since Linux 5.14 the count is kept per user namespace, and every run has its own,
so the process limit of one run is exact even with several runs side by side; the suite
proves a fork bomb does not starve a concurrent run. The container's `pids_limit` and
`mem_limit` remain the final bound, and every run's `oom_score_adj` is 1000, so under
memory pressure the kernel kills a sandboxed program, never the service.

## Measuring

The service starts `agentguard-sandbox-measure` (`native/measure.c`, static), which raises
its `oom_score_adj`, forks nsjail and waits for it with `wait4`. The `rusage` of nsjail
includes every process of the sandbox it reaped:

- **CPU time** is `ru_utime + ru_stime`, summed over threads and children and unaffected
  by sleeping or by other load (a program that sleeps for a second uses about
  15 ms).
- **Peak memory** is `ru_maxrss`, the largest resident set of any process in the sandbox.

The helper exists because Linux also carries peak memory across `fork`: anything the
service (a Python process of tens of megabytes) started directly would report at least
the service's own peak. Measured in the image (arm64, Docker Desktop): bash `true` takes 11 ms and
reads 7 MB (nsjail itself), Python `print(1)` 17 ms and 9 MB, Node 37 ms and 40 MB, Python
touching 100 MB reads 111 MB, and a Python program sleeping one second uses 15 ms of CPU.

## Verdicts

In this order: `error` (the sandbox could not start the program, or a request above the
service's maximum), `output_limit` (stdout or stderr passed the cap, or `SIGXFSZ`; before
the time limit because a program cut off mid-print may then spin), `timeout` (wall clock,
CPU time over the limit, or `SIGXCPU`), `memory` (an out-of-memory message on a failed
run, Node's peak over the limit, or a death at 90% of the limit or more), `killed` (any
other signal), `nonzero_exit`, `ok`.

## Network modes

**`none`**: the run gets a new network namespace with no interface up. `connect()` fails,
DNS fails, abstract unix sockets of the service are invisible (they belong to the
service's network namespace). There is no way out.

**`proxy`**: the program still runs in its own new network namespace, so it can never
reach the API, Postgres, Redis or the metadata service directly. Its only way out is the
egress proxy, which decides every connection under the agent's network policy and records
it (AC12):

1. For the run, the service creates a unix socket in the run's own directory and listens
   on it (`relay.py`). The directory holding only that socket is bind-mounted read-only
   into the sandbox at `/run/egress`.
2. Inside the sandbox, loopback is up. `agentguard-sandbox-init` binds `127.0.0.1:3128`
   before the program starts and forks a forwarder that relays each TCP connection to
   `/run/egress/egress.sock`. `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy` and `https_proxy`
   are `http://127.0.0.1:3128`, `NO_PROXY` is empty (and `NODE_USE_ENV_PROXY=1` so Node's
   `fetch` honours them); proxy variables the request set itself are replaced.
3. The relay, outside the sandbox, reads the first request head of each connection. It
   accepts only an HTTP `CONNECT host:port` or an absolute-form `GET http://...` proxy
   request (anything else gets 400), removes every `Proxy-Authorization` the program sent,
   adds `Proxy-Authorization: <proxy_authorization>` (the agent's identity, given by the
   API in the request and validated as one header value), forces `Connection: close` on
   plain HTTP so one connection carries one authenticated request, connects to
   `proxy_url` and nowhere else, whatever the request names, and relays bytes both ways.
   At most 32 connections per run are relayed at once.
4. After the run the relay stops, its connections are cancelled, and the socket and the
   run directory are removed.

The credential never enters the sandbox: not in the environment, not in a file, not on
the socket (it is added on the far side). The forwarder is a convenience and not a
security boundary: the program may kill it or speak to the unix socket directly, and
gains nothing, because the relay is what talks to the proxy. Other runs' sockets live in
other run directories that this sandbox does not mount.

## The isolation backend interface

`isolation.py` defines `Isolator`: `execute(RunSpec) -> Execution`. The runner prepares a
run and the backend runs it; nothing else depends on how. Two implementations exist:

- `NsjailIsolator` (`nsjail.py`), the only one used in the image.
- `DevFallbackIsolator` (`fallback.py`), for working on the service itself on a machine
  without nsjail. It runs the program directly, with **no isolation**, only when
  `SANDBOX_ALLOW_DEV_FALLBACK=true`; `/healthz` reports `dev-fallback`, every result says
  so in `detail`, and network mode `proxy` is refused.

## What this does not protect against

- **Kernel vulnerabilities reachable through namespaces.** User namespaces widen the
  kernel's attack surface: a privilege escalation bug in a namespace code path could let
  a program out. The syscall filter removes the common entry points (`unshare`,
  `io_uring`, `bpf`, `userfaultfd`), and an escape still lands as an unprivileged user in
  an unprivileged container holding one token, but it is not impossible. There is no gVisor
  or Firecracker backend yet: the `Isolator` interface is where one goes (a `runsc` or
  microVM implementation chosen by configuration, with no change to the runner or the
  API). Until then, for code from untrusted parties, run the sandbox containers under
  gVisor (`runsc`) or Kata Containers, or on dedicated hosts, and keep the kernel patched.
- **Side channels.** Timing and cache side channels between concurrent runs are not
  addressed.
- **CPU time spread over processes.** `RLIMIT_CPU` is per process; a program that forks
  workers can use up to its wall clock in total (one core, `--max_cpus 1`). The verdict is
  still `timeout` from the measured total.
- **Node's off-heap memory.** Node's address ceiling includes what V8 reserves, so a
  Buffer-heavy program can briefly exceed `memory_mb` before it fails or its peak is judged
  `memory`; the container limit bounds it.
- **What the egress proxy allows.** Proxy mode gives exactly the agent's network policy;
  the sandbox adds no policy of its own.

## Running the hostile suite

```sh
scripts/test-sandbox.sh            # build the image, run apps/api/tests/sandbox inside it
scripts/test-sandbox.sh -k proxy   # extra arguments go to pytest
SANDBOX_SKIP_BUILD=1 scripts/test-sandbox.sh
```

The script runs the suite inside the real image with the production hardening (every
capability dropped, no-new-privileges, the custom seccomp profile, a read-only root, tmpfs
scratch, pids and memory limits, no network) against the real runner, nsjail and
toolchains. It covers fork, thread and spawn bombs (and one running beside a normal run),
memory bombs in all three languages, CPU spins, sleepers and programs blocked on stdin,
stdout and stderr floods, files past `file_bytes`, filling the scratch directory, writes
outside scratch, reading host files, the service's files and environment
(`SANDBOX_TOKEN`), `kill -9 -1`, namespace, mount and ptrace calls, spawning a shell and a
bash reverse shell, every TCP, UDP, DNS and abstract-socket path in mode `none`, and in
mode `proxy` the credential injection, stripping of a forged credential, CONNECT tunnels,
Node's `fetch`, an unreachable proxy, and that nothing but the proxy is reachable (a fake
proxy in the test records what reached it). After every hostile test a normal run in
every language must return the right answer.

Validation, the token and body gate, the header rewrite, verdicts and the nsjail command
line are unit tested without Docker in `apps/api/tests/unit/test_sandbox_service.py`,
which also fails if this service's schemas drift from the API client's.

Report sandbox escapes privately: [SECURITY.md](../../SECURITY.md).
