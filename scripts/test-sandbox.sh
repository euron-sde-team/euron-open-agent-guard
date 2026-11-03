#!/usr/bin/env bash
# Build the sandbox image and run the hostile suite (apps/api/tests/sandbox) inside it,
# with exactly the hardening production gives the sandbox service: every capability
# dropped, no-new-privileges, the custom seccomp profile, a read-only root, tmpfs scratch
# owned by the service user, pids and memory limits, and no network.
#
#   scripts/test-sandbox.sh                 build, then run the whole suite
#   scripts/test-sandbox.sh -k proxy        extra arguments go to pytest
#   SANDBOX_SKIP_BUILD=1 scripts/test-sandbox.sh   reuse the image built last time
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${SANDBOX_TEST_IMAGE:-agentguard-sandbox-test:local}"

# The same flags as the sandbox service in deploy/compose/compose.yaml.
HARDENING=(
  --cap-drop ALL
  --security-opt no-new-privileges
  --security-opt "seccomp=$ROOT/infra/docker/sandbox-seccomp.json"
  --read-only
  --tmpfs /tmp:exec,size=1g,uid=10001,gid=10001,mode=0700
  --pids-limit 512
  --memory 3g
  --cpus 2
  --network none
)

if [[ "${SANDBOX_SKIP_BUILD:-0}" != "1" ]]; then
  docker build -f "$ROOT/infra/docker/sandbox.Dockerfile" --target sandbox-test \
    -t "$IMAGE" "$ROOT/apps/api"
fi

# The tests are mounted read-only; --confcutdir keeps pytest from loading the API's own
# conftest files, which need packages this image does not carry.
docker run --rm "${HARDENING[@]}" -e PYTHONDONTWRITEBYTECODE=1 \
  -v "$ROOT/apps/api/tests:/src/tests:ro" \
  -v "$ROOT/apps/api/pyproject.toml:/src/pyproject.toml:ro" \
  -w /src "$IMAGE" \
  pytest -q -p no:cacheprovider --confcutdir tests/sandbox tests/sandbox "$@"
