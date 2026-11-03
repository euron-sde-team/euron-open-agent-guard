#!/usr/bin/env bash
# Make sure the services the integration suite talks to are reachable: Postgres, Redis,
# OPA, Vault, the sandbox (through sandbox-gateway on 5135) and the mock services (model,
# OIDC, TokenShield, demo tools and MCP servers).
# Reuses the Compose services when the stack is up; otherwise starts just those. Tests
# never use a host-installed Postgres or Redis.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="$ROOT/deploy/compose/.env"
port() { local v; v="$(grep -s "^$1=" "$ENV_FILE" | cut -d= -f2 || true)"; echo "${v:-$2}"; }

ready() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

missing=()
ready "$(port AG_PG_PORT 5142)" || missing+=(postgres)
ready "$(port AG_REDIS_PORT 5179)" || missing+=(redis)
ready "$(port AG_OPA_PORT 5181)" || missing+=(opa)
ready "$(port AG_VAULT_PORT 5182)" || missing+=(vault)
ready "$(port AG_MOCK_AI_PORT 5150)" || missing+=(mockai)
ready "$(port AG_SANDBOX_PORT 5135)" || missing+=(sandbox sandbox-gateway)
((${#missing[@]})) || exit 0

"$ROOT/scripts/gen-local-env.sh" >/dev/null
echo "starting ${missing[*]}"
docker compose --env-file "$ENV_FILE" -f "$ROOT/deploy/compose/compose.yaml" \
  up -d --wait "${missing[@]}"
