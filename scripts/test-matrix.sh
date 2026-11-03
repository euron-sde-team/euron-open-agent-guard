#!/usr/bin/env bash
# Run the API integration suite under every backend combination AgentGuard supports:
#
#   keys:          local key file (AES-GCM)        | AWS KMS (Floci)
#   secret store:  database (envelope encrypted)   | HashiCorp Vault KV v2 (Compose)
#   redis:         on (shared counters, nonces, fan-out) | off (in-process, one replica)
#
# 2 x 2 x 2 = 8 runs. Passed to the suite as KEY_MODE, TEST_SECRET_STORE and TEST_REDIS_URL
# (empty for off). Needs Floci with the local-floci Terraform applied (make up) for the
# KMS runs. Each combination gets its own test database, so a run never reuses another's
# state.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="$ROOT/deploy/compose/.env"
port() { local v; v="$(grep -s "^$1=" "$ENV_FILE" | cut -d= -f2 || true)"; echo "${v:-$2}"; }
FLOCI_URL="http://localhost:$(port AG_FLOCI_PORT 5166)"
PG="postgresql+asyncpg://agentguard:agentguard@localhost:$(port AG_PG_PORT 5142)"
REDIS="redis://localhost:$(port AG_REDIS_PORT 5179)/14"

if ! curl -sf -o /dev/null "$FLOCI_URL/"; then
  echo "Floci is not reachable at $FLOCI_URL. Start the stack first: make up" >&2
  exit 1
fi
"$ROOT/scripts/test-db.sh"

# KMS on the emulator: the key the local-floci Terraform created.
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_REGION=us-east-1
export TEST_AWS_ENDPOINT="$FLOCI_URL"
export KMS_KEY_ID=alias/agentguard-local TEST_KMS_KEY_ID=alias/agentguard-local
export TEST_OPA_URL="http://localhost:$(port AG_OPA_PORT 5181)"
export TEST_VAULT_URL="http://localhost:$(port AG_VAULT_PORT 5182)"
export TEST_VAULT_TOKEN="$(port AG_VAULT_TOKEN '')"
export TEST_MOCKAI_URL="http://localhost:$(port AG_MOCK_AI_PORT 5150)"
export TEST_SANDBOX_URL="http://localhost:$(port AG_SANDBOX_PORT 5135)"
export TEST_SANDBOX_TOKEN="$(port SANDBOX_TOKEN '')"
failed=()
runs=0
for keys in local kms; do
  for store in database vault; do
    for redis in on off; do
      runs=$((runs + 1))
      echo
      echo "== keys=$keys secret_store=$store redis=$redis"
      redis_url=""; [[ "$redis" == on ]] && redis_url="$REDIS"
      aws_endpoint=""; [[ "$keys" == kms ]] && aws_endpoint="$FLOCI_URL"
      if ! (cd "$ROOT/apps/api" && KEY_MODE=$keys TEST_SECRET_STORE=$store \
            AWS_ENDPOINT_URL="$aws_endpoint" \
            TEST_DATABASE_URL="$PG/agentguard_test_matrix_${keys}_${store}_${redis}" \
            TEST_REDIS_URL="$redis_url" \
            uv run pytest tests/integration -m integration -q -p no:warnings -rf); then
        failed+=("keys=$keys secret_store=$store redis=$redis")
      fi
    done
  done
done
echo
if ((${#failed[@]})); then
  printf 'matrix: FAILED for %s\n' "${failed[@]}"
  exit 1
fi
echo "matrix: all $runs combinations passed"
