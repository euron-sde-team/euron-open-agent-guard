#!/usr/bin/env bash
# Back up the local stack: a consistent Postgres dump (the audit chain included) and a
# copy of the objects bucket (evidence, exports) and the audit checkpoint bucket. Writes
# backups/<timestamp>/ next to the repository.
#   make backup              # then: make restore BACKUP=backups/<timestamp>
# On AWS use RDS snapshots and S3 versioning instead (docs/guides/operations.md).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE=(docker compose --env-file "$ROOT/deploy/compose/.env" -f "$ROOT/deploy/compose/compose.yaml" -f "$ROOT/deploy/compose/compose.floci.yaml")
DEST="$ROOT/backups/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$DEST/objects" "$DEST/audit"

# pg_dump runs in one transaction, so the dump is consistent while the app keeps serving.
"${COMPOSE[@]}" exec -T postgres pg_dump -U agentguard -d agentguard --format=custom > "$DEST/agentguard.dump"

# The buckets, through the emulator's S3 API (the same commands work against AWS).
for bucket in objects audit; do
  docker run --rm --network agentguard_default -v "$DEST/$bucket:/backup" \
    -e AWS_ACCESS_KEY_ID=test -e AWS_SECRET_ACCESS_KEY=test -e AWS_DEFAULT_REGION=us-east-1 \
    amazon/aws-cli:2.31.18 --endpoint-url http://floci:4566 s3 sync "s3://agentguard-local-$bucket" /backup --only-show-errors
done

echo "backup written to ${DEST#"$ROOT"/} ($(du -sh "$DEST" | cut -f1))"
