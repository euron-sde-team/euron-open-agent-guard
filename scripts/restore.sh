#!/usr/bin/env bash
# Restore a backup made by scripts/backup.sh into the running local stack. Replaces the
# database contents and re-uploads the objects. Stops the api, the worker, the egress proxy
# and the web app first so nothing writes while the database is replaced.
#
# The audit log is append-only in the database (updates and deletes are refused), so the
# restore drops and recreates the schema with pg_restore --clean rather than editing rows.
# Audit checkpoints already in the Object Lock bucket stay (they cannot be overwritten);
# the backup's checkpoints are uploaded next to them.
#   make restore BACKUP=backups/<timestamp>
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${1:?usage: scripts/restore.sh backups/<timestamp>}"
[[ "$SRC" = /* ]] || SRC="$ROOT/$SRC"
[[ -f "$SRC/agentguard.dump" ]] || { echo "no agentguard.dump in $SRC"; exit 1; }
COMPOSE=(docker compose --env-file "$ROOT/deploy/compose/.env" -f "$ROOT/deploy/compose/compose.yaml" -f "$ROOT/deploy/compose/compose.floci.yaml")

"${COMPOSE[@]}" stop web api worker egress
"${COMPOSE[@]}" exec -T postgres pg_restore -U agentguard -d agentguard --clean --if-exists --no-owner < "$SRC/agentguard.dump"
for bucket in objects audit; do
  [[ -d "$SRC/$bucket" ]] || continue
  docker run --rm --network agentguard_default -v "$SRC/$bucket:/backup:ro" \
    -e AWS_ACCESS_KEY_ID=test -e AWS_SECRET_ACCESS_KEY=test -e AWS_DEFAULT_REGION=us-east-1 \
    amazon/aws-cli:2.31.18 --endpoint-url http://floci:4566 s3 sync /backup "s3://agentguard-local-$bucket" --only-show-errors
done
"${COMPOSE[@]}" up -d --wait api worker egress web
echo "restored ${SRC#"$ROOT"/}"
