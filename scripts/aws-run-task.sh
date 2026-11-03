#!/usr/bin/env bash
# Run a one-off `agentguard` command as an ECS task, wait for it, print its logs.
#   scripts/aws-run-task.sh <aws-dev|aws-prod> migrate
#   AGENTGUARD_ADMIN_PASSWORD=... scripts/aws-run-task.sh aws-dev create-admin --email you@example.com
#   scripts/aws-run-task.sh aws-dev seed-demo
# The command runs as arguments to the `agentguard` CLI (the image's entrypoint) on the
# migrate task definition.
#
# AGENTGUARD_ADMIN_PASSWORD never travels as an ECS override (overrides stay readable to
# anyone allowed to describe the task). It is written to the bootstrap secret, which only
# the migrate task definition injects; the task reads it from there, and the secret is
# overwritten with a random value as soon as the task stops, whatever its outcome.
set -euo pipefail
ENV="${1:?usage: aws-run-task.sh <env> <agentguard command...>}"; shift
DIR="$(cd "$(dirname "$0")/.." && pwd)/infra/terraform/envs/$ENV"
spec=$(terraform -chdir="$DIR" output -json run_task)
get() { echo "$spec" | python3 -c "import json,sys; v=json.load(sys.stdin)['$1']; print(','.join(v) if isinstance(v, list) else v)"; }
cluster=$(get cluster); taskdef=$(get task_definition); container=$(get container)

# put_bootstrap <password>: the JSON goes through a private temp file, never argv.
put_bootstrap() {
  local secret tmp
  secret=$(terraform -chdir="$DIR" output -raw bootstrap_secret_arn)
  tmp=$(umask 077 && mktemp)
  PW="$1" python3 -c 'import json, os; print(json.dumps({"AGENTGUARD_ADMIN_PASSWORD": os.environ["PW"]}))' > "$tmp"
  aws secretsmanager put-secret-value --secret-id "$secret" --secret-string "file://$tmp" >/dev/null
  rm -f "$tmp"
}
scrub() { put_bootstrap "$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"; }

if [[ -n "${AGENTGUARD_ADMIN_PASSWORD:-}" ]]; then
  put_bootstrap "$AGENTGUARD_ADMIN_PASSWORD"
  trap scrub EXIT
fi

overrides=$(python3 - "$container" "$@" <<'PY'
import json, sys
container, *command = sys.argv[1:]
print(json.dumps({"containerOverrides": [{"name": container, "command": command}]}))
PY
)
network="awsvpcConfiguration={subnets=[$(get subnets)],securityGroups=[$(get security_groups)],assignPublicIp=DISABLED}"
arn=$(aws ecs run-task --cluster "$cluster" --task-definition "$taskdef" --launch-type FARGATE \
  --network-configuration "$network" --overrides "$overrides" \
  --query 'tasks[0].taskArn' --output text)
echo "started $arn"
aws ecs wait tasks-stopped --cluster "$cluster" --tasks "$arn"
code=$(aws ecs describe-tasks --cluster "$cluster" --tasks "$arn" --query 'tasks[0].containers[0].exitCode' --output text)
group=$(aws ecs describe-task-definition --task-definition "$taskdef" \
  --query 'taskDefinition.containerDefinitions[0].logConfiguration.options."awslogs-group"' --output text)
aws logs tail "$group" --since 15m --format short | tail -40
echo "exit code: $code"
[[ "$code" == "0" ]]
