#!/usr/bin/env bash
# Write deploy/compose/.env with random, local-only secrets (once; never overwrites).
# deploy/compose/.env.example documents every variable it may hold.
set -euo pipefail
f="$(cd "$(dirname "$0")/.." && pwd)/deploy/compose/.env"
if [[ -f "$f" ]]; then
  echo "deploy/compose/.env exists (delete it to regenerate)"
  exit 0
fi
rand() { openssl rand -base64 48 | tr -d '/+=\n' | cut -c1-"$1"; }
umask 077
# SESSION_SECRET, TOKEN_PEPPER and SANDBOX_TOKEN must all differ (the API refuses to boot
# otherwise in production); independent draws of 64 characters always do. The demo
# password is the published login of the seeded demo company (`make demo`), not a secret.
cat > "$f" <<ENV
SESSION_SECRET=$(rand 64)
TOKEN_PEPPER=$(rand 64)
LOCAL_MASTER_KEY=$(rand 64)
SANDBOX_TOKEN=$(rand 64)
AG_VAULT_TOKEN=$(rand 40)
AG_DEMO_PASSWORD=${AG_DEMO_PASSWORD:-Demo-Pass-2026}
ENV
echo "wrote deploy/compose/.env"
