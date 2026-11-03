# syntax=docker/dockerfile:1.7
# =====================================================================================
# The sandbox service: the only place AgentGuard runs untrusted code.
#   docker build -f infra/docker/sandbox.Dockerfile --target sandbox -t agentguard-sandbox apps/api
#
# It runs agentguard-sandbox (FastAPI on 0.0.0.0:8080) and starts one nsjail per run,
# built from user namespaces so the container itself needs no privilege. Compose and
# the hostile suite (scripts/test-sandbox.sh) drop every capability, set no-new-privileges,
# a read-only root and infra/docker/sandbox-seccomp.json (docs/architecture/sandbox.md).
#
# Runtimes offered to sandboxed code: Python 3.12, Node.js 22 and bash.
# =====================================================================================
ARG PYTHON_IMAGE=python:3.12.13-slim-bookworm
ARG NODE_IMAGE=node:22.21.1-bookworm-slim
ARG NSJAIL_VERSION=3.6

FROM ghcr.io/astral-sh/uv:0.11.19 AS uv
FROM ${NODE_IMAGE} AS node

# nsjail (pinned release tag) and the two static helpers, on the runtime's Debian
FROM ${PYTHON_IMAGE} AS nsjail
ARG NSJAIL_VERSION
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates git make g++ pkg-config bison flex protobuf-compiler \
      libprotobuf-dev libnl-route-3-dev \
 && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch "${NSJAIL_VERSION}" https://github.com/google/nsjail.git /src \
 && make -C /src -j"$(nproc)" \
 && install -m 0755 /src/nsjail /nsjail
# Two small static helpers (see their sources for why they are not Python): the one that
# measures each run from outside, and the first process inside each sandbox.
COPY src/agentguard_sandbox/native/ /native/
RUN gcc -O2 -Wall -Wextra -Werror -static -o /agentguard-sandbox-measure /native/measure.c \
 && gcc -O2 -Wall -Wextra -Werror -static -o /agentguard-sandbox-init /native/init.c

# The service's virtualenv: only the sandbox dependency group from uv.lock
FROM ${PYTHON_IMAGE} AS build
COPY --from=uv /uv /bin/
ARG UV_CONCURRENT_DOWNLOADS=4
ARG UV_HTTP_TIMEOUT=300
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv UV_HTTP_RETRIES=8
WORKDIR /src
# The sandbox needs FastAPI, uvicorn and pydantic, not the API's database, AWS or AI
# libraries, so it installs one dependency group and none of the project's own code.
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --only-group sandbox
COPY src/agentguard_sandbox /opt/venv/lib/python3.12/site-packages/agentguard_sandbox
RUN python -m compileall -q /opt/venv/lib/python3.12/site-packages/agentguard_sandbox \
 && printf '#!/opt/venv/bin/python\nfrom agentguard_sandbox.cli import main\nraise SystemExit(main())\n' \
      > /opt/venv/bin/agentguard-sandbox \
 && chmod 0755 /opt/venv/bin/agentguard-sandbox

# Runtime
FROM ${PYTHON_IMAGE} AS sandbox
RUN apt-get update && apt-get install -y --no-install-recommends \
      tini ca-certificates bash libprotobuf32 libnl-route-3-200 libstdc++6 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=nsjail /nsjail /usr/local/bin/nsjail
COPY --from=nsjail /agentguard-sandbox-measure /agentguard-sandbox-init /usr/local/bin/
# Only the node binary: no npm, no corepack, nothing that installs packages at run time.
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=build /opt/venv /opt/venv
# The service lives in /opt, which no sandbox mounts: sandboxed code sees /usr, /lib, /bin
# and a few files read-only, its own scratch tmpfs, and nothing of the service.
ENV PATH=/opt/venv/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 TZ=UTC HOME=/tmp \
    SANDBOX_HOST=0.0.0.0 SANDBOX_PORT=8080 SANDBOX_SCRATCH_DIR=/tmp/agentguard-sandbox \
    NSJAIL_PATH=/usr/local/bin/nsjail
RUN groupadd --system --gid 10001 sandbox \
 && useradd --system --uid 10001 --gid sandbox --home-dir /tmp --no-create-home \
      --shell /usr/sbin/nologin sandbox
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).status == 200 else 1)"
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["agentguard-sandbox"]

# Test target: the same image plus pytest (scripts/test-sandbox.sh mounts the tests)
FROM build AS build-test
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --only-group sandbox --only-group sandbox-test --inexact

FROM sandbox AS sandbox-test
COPY --from=build-test /opt/venv /opt/venv
WORKDIR /src
CMD ["pytest", "-q", "-p", "no:cacheprovider", "--confcutdir", "tests/sandbox", "tests/sandbox"]
