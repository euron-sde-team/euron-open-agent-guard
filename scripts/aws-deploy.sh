#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# One-shot deployment to AWS:  scripts/aws-deploy.sh <aws-dev|aws-prod> <image-tag>
#
#   1. terraform apply the image registries (and the KMS key that encrypts them)
#   2. build the server, web and sandbox images for the clusters' CPU architecture and
#      push them
#   3. terraform apply everything else, the services still on the tag they run now and
#      only the migrate task on the new one
#   4. run the database migrations as a one-off ECS task, before any new code serves
#   5. terraform apply again with the new tag everywhere: the services roll onto it
#   6. wait for the api, worker, egress, web and sandbox services to become stable
#
# Migrations go first so new code never runs against an old schema; a failed migration
# stops the deploy with the previous release still serving. Migrations must therefore
# stay backward compatible with the release before them (add, then remove a release
# later). On the very first deploy there is no previous release: the services start with
# the new tag and become usable once step 4 has created the schema.
#
# Needs: terraform, docker (buildx), the AWS CLI, credentials for the target account,
# and infra/terraform/envs/<env>/terraform.tfvars (copy the .example next to it).
# This repository never runs it against a real account itself; it is here so you can.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
ENV="${1:?usage: aws-deploy.sh <aws-dev|aws-prod> <image-tag>}"
TAG="${2:?usage: aws-deploy.sh <aws-dev|aws-prod> <image-tag>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$ROOT/infra/terraform/envs/$ENV"
PLATFORM="${PLATFORM:-linux/arm64}"   # matches the service module's default cpu_architecture

for bin in terraform docker aws python3; do command -v "$bin" >/dev/null || { echo "missing: $bin"; exit 1; }; done
[[ -f "$DIR/terraform.tfvars" ]] || { echo "create $DIR/terraform.tfvars from terraform.tfvars.example first"; exit 1; }
[[ -n "$(git -C "$ROOT" status --porcelain 2>/dev/null)" ]] && echo "note: the working tree has uncommitted changes; the images are built from it as-is"

tf() { terraform -chdir="$DIR" "$@"; }
json() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }

echo "==> terraform init"
tf init -input=false >/dev/null

# The tag the services run now, read before any apply touches the outputs (empty on the
# first deploy).
current=$(tf output -raw image_tag 2>/dev/null || true)
current="${current:-$TAG}"

echo "==> 1/6 registries"
tf apply -input=false -auto-approve -var "image_tag=$current" -target=module.ecr

region="${AWS_REGION:-$(aws configure get region 2>/dev/null || true)}"
region="${region:-$(grep -E '^region' "$DIR/terraform.tfvars" | sed -E 's/.*"(.*)".*/\1/')}"
repos=$(tf output -json ecr_repositories)
server_repo=$(echo "$repos" | json "['server']")
web_repo=$(echo "$repos" | json "['web']")
sandbox_repo=$(echo "$repos" | json "['sandbox']")
aws ecr get-login-password --region "$region" | docker login --username AWS --password-stdin "${server_repo%%/*}" >/dev/null

echo "==> 2/6 images ($TAG, $PLATFORM)"
# One image runs the api, the worker, the egress proxy, migrate and the CLI.
docker buildx build --platform "$PLATFORM" -f "$ROOT/infra/docker/server.Dockerfile" --target server \
  -t "$server_repo:$TAG" --push "$ROOT/apps/api"
docker buildx build --platform "$PLATFORM" -f "$ROOT/infra/docker/web.Dockerfile" \
  -t "$web_repo:$TAG" --push "$ROOT/apps/web"
docker buildx build --platform "$PLATFORM" -f "$ROOT/infra/docker/sandbox.Dockerfile" --target sandbox \
  -t "$sandbox_repo:$TAG" --push "$ROOT/apps/api"

echo "==> 3/6 infrastructure (services stay on $current, migrate on $TAG)"
tf apply -input=false -auto-approve -var "image_tag=$current" -var "migrate_image_tag=$TAG"

echo "==> 4/6 migrations"
"$ROOT/scripts/aws-run-task.sh" "$ENV" migrate

echo "==> 5/6 services onto $TAG"
tf apply -input=false -auto-approve -var "image_tag=$TAG"

echo "==> 6/6 waiting for the services"
cluster=$(tf output -raw cluster_name)
services=$(tf output -json services | python3 -c "import json,sys; print(' '.join(json.load(sys.stdin).values()))")
# shellcheck disable=SC2086 # one argument per service name
aws ecs wait services-stable --region "$region" --cluster "$cluster" --services $services
aws ecs wait services-stable --region "$region" --cluster "$(tf output -raw sandbox_cluster_name)" --services sandbox

echo
echo "Deployed $TAG to $ENV: $(tf output -raw url)"
cat <<NEXT
Next:
  AGENTGUARD_ADMIN_PASSWORD='...' make aws-admin ENV=$ENV EMAIL=you@example.com ORG='Your Company'
Then publish the DKIM records (tf output dkim_records) if no Route53 zone was given,
request SES production access before approval mail goes to unverified reviewers, and
point your agents' HTTP_PROXY / HTTPS_PROXY at $(tf output -raw egress_proxy_url).
NEXT
