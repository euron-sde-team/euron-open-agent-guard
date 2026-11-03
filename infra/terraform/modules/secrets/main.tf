# AgentGuard's own secrets, in Secrets Manager. ECS injects each JSON key into the
# containers that need it as an environment variable; the values never appear in a task
# definition, a plan diff or a log. Each consumer gets only its own keys (see the outputs).
#
# Four secrets with different lifecycles and readers:
#
#   <name_prefix>/app           SESSION_SECRET, TOKEN_PEPPER, SANDBOX_TOKEN. Read by the
#                               api, the worker, the egress proxy and the migrate task;
#                               the sandbox gets SANDBOX_TOKEN and nothing else.
#                               TOKEN_PEPPER peppers the hashes of API keys, agent client
#                               secrets and invitation tokens; SANDBOX_TOKEN authenticates
#                               every call to the sandbox.
#   <name_prefix>/connections   DATABASE_URL (it carries the generated RDS password) and
#                               REDIS_URL (with the AUTH token). Derived from the database
#                               and cache modules and kept in step with them on every apply.
#   <name_prefix>/integrations  VAULT_TOKEN for the optional
#                               HashiCorp Vault secret store. Empty
#                               until the operator puts values in (never through Terraform).
#   <name_prefix>/bootstrap     AGENTGUARD_ADMIN_PASSWORD, read only by the one-off migrate
#                               task: `make aws-admin` puts the first owner's password here,
#                               runs `create-admin`, then overwrites it with a random value.
#                               The password never travels as an ECS task override (those
#                               stay readable to anyone allowed to describe the task).
#
# Generated once, then rotated out of band; Terraform never rolls them back. The values
# are distinct on purpose (the API refuses to boot in production unless SESSION_SECRET,
# TOKEN_PEPPER and SANDBOX_TOKEN all differ). Locally (Compose) the same values come from
# deploy/compose/.env; on AWS no LOCAL_MASTER_KEY is needed because stored secrets are
# wrapped with KMS (KEY_MODE=kms).
locals {
  app_keys         = ["SESSION_SECRET", "TOKEN_PEPPER", "SANDBOX_TOKEN"]
  connection_keys  = var.include_connection_urls ? ["DATABASE_URL", "REDIS_URL"] : []
  integration_keys = ["VAULT_TOKEN"]
}

resource "random_password" "this" {
  for_each = toset(concat(local.app_keys, ["AGENTGUARD_ADMIN_PASSWORD"]))
  length   = 64
  special  = false
}

resource "aws_secretsmanager_secret" "app" {
  #checkov:skip=CKV2_AWS_57:These are HMAC keys and a shared bearer token; rotation is an operator procedure (docs/guides/operations.md), not a Lambda.
  name                    = "${var.name_prefix}/app"
  description             = "AgentGuard signing secrets (sessions, token pepper, sandbox token)"
  kms_key_id              = var.kms_key_arn
  recovery_window_in_days = var.recovery_window_in_days
}

resource "aws_secretsmanager_secret_version" "app" {
  secret_id     = aws_secretsmanager_secret.app.id
  secret_string = jsonencode({ for k in local.app_keys : k => random_password.this[k].result })

  # Rotation happens out of band (put a new version by hand or by pipeline). Without
  # this, the next `terraform apply` would quietly roll every secret back.
  lifecycle {
    ignore_changes = [secret_string]
  }
}

resource "aws_secretsmanager_secret" "connections" {
  #checkov:skip=CKV2_AWS_57:Derived values; they change when the database or cache module rotates its credential.
  count                   = var.include_connection_urls ? 1 : 0
  name                    = "${var.name_prefix}/connections"
  description             = "AgentGuard connection URLs (PostgreSQL with its password, Redis/Valkey with its AUTH token)"
  kms_key_id              = var.kms_key_arn
  recovery_window_in_days = var.recovery_window_in_days
}

resource "aws_secretsmanager_secret_version" "connections" {
  count     = var.include_connection_urls ? 1 : 0
  secret_id = aws_secretsmanager_secret.connections[0].id
  secret_string = jsonencode({
    DATABASE_URL = var.database_url
    REDIS_URL    = var.redis_url
  })
}

resource "aws_secretsmanager_secret" "integrations" {
  #checkov:skip=CKV2_AWS_57:Tokens issued by external systems (Vault, TokenShield); they rotate there and are put here by the operator.
  name                    = "${var.name_prefix}/integrations"
  description             = "AgentGuard tokens for optional integrations (Vault, TokenShield); empty until set"
  kms_key_id              = var.kms_key_arn
  recovery_window_in_days = var.recovery_window_in_days
}

resource "aws_secretsmanager_secret_version" "integrations" {
  secret_id     = aws_secretsmanager_secret.integrations.id
  secret_string = jsonencode({ for k in local.integration_keys : k => "" })

  # The operator writes the real tokens (docs/guides/deploy-aws.md).
  lifecycle {
    ignore_changes = [secret_string]
  }
}

resource "aws_secretsmanager_secret" "bootstrap" {
  #checkov:skip=CKV2_AWS_57:Holds a random placeholder except for the seconds `make aws-admin` runs create-admin; nothing to rotate.
  name                    = "${var.name_prefix}/bootstrap"
  description             = "AgentGuard first-owner password for the one-off create-admin task (random placeholder otherwise)"
  kms_key_id              = var.kms_key_arn
  recovery_window_in_days = var.recovery_window_in_days
}

resource "aws_secretsmanager_secret_version" "bootstrap" {
  secret_id     = aws_secretsmanager_secret.bootstrap.id
  secret_string = jsonencode({ AGENTGUARD_ADMIN_PASSWORD = random_password.this["AGENTGUARD_ADMIN_PASSWORD"].result })

  # scripts/aws-run-task.sh writes and then scrubs this value.
  lifecycle {
    ignore_changes = [secret_string]
  }
}

locals {
  # api, worker, egress and migrate.
  ecs_secrets = concat(
    [for k in local.app_keys : { name = k, valueFrom = "${aws_secretsmanager_secret.app.arn}:${k}::" }],
    [for k in local.connection_keys : { name = k, valueFrom = "${aws_secretsmanager_secret.connections[0].arn}:${k}::" }],
    [for k in local.integration_keys : { name = k, valueFrom = "${aws_secretsmanager_secret.integrations.arn}:${k}::" }],
  )
  # The sandbox: its bearer token only. It holds no database, cache or signing secret.
  sandbox_secrets = [
    { name = "SANDBOX_TOKEN", valueFrom = "${aws_secretsmanager_secret.app.arn}:SANDBOX_TOKEN::" },
  ]
  # The migrate task only.
  bootstrap_secrets = [
    { name = "AGENTGUARD_ADMIN_PASSWORD", valueFrom = "${aws_secretsmanager_secret.bootstrap.arn}:AGENTGUARD_ADMIN_PASSWORD::" },
  ]
}
