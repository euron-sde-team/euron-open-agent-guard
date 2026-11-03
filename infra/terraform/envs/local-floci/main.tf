# ─────────────────────────────────────────────────────────────────────────────
# Local environment on the Floci AWS emulator.
#
# The modules that build production run here unchanged; only the provider endpoints
# differ. `make up` applies this automatically (the compose `tf-local-floci` one-shot)
# before migrate, api, worker and egress start, so local development uses KMS, S3 (with
# Object Lock for audit checkpoints), Secrets Manager and SES exactly as AWS does. By
# hand, against a running emulator:
#
#   terraform -chdir=infra/terraform/envs/local-floci init
#   terraform -chdir=infra/terraform/envs/local-floci apply -var endpoint=http://localhost:5166
#
# Postgres and Redis are plain Compose containers locally (the emulator does not back RDS
# or ElastiCache), and so are OPA, Vault and the sandbox. The network, database, cache,
# ecr, service, sandbox and observability modules are exercised by aws-dev and aws-prod
# (make tf-validate, make tf-aws-on-floci).
# ─────────────────────────────────────────────────────────────────────────────

module "kms" {
  source                  = "../../modules/kms"
  name_prefix             = var.name_prefix
  deletion_window_in_days = 7
}

# GOVERNANCE with a one-day lock, so `make down` and a fresh `make up` start clean; AWS
# environments lock in COMPLIANCE mode.
module "storage" {
  source               = "../../modules/storage"
  name_prefix          = var.name_prefix
  kms_key_arn          = module.kms.key_arn
  enforce_tls          = false # the emulator speaks plain HTTP
  force_destroy        = true
  audit_force_destroy  = true
  audit_lock_mode      = "GOVERNANCE"
  audit_retention_days = 1
  cors_origins         = var.cors_origins
}

# Generated secrets are an AWS-deployment concern; locally compose reads
# deploy/compose/.env (make env). Created here anyway so the module is exercised, and so
# AWS Secrets Manager has something real behind it as an external secret store.
module "secrets" {
  source                  = "../../modules/secrets"
  name_prefix             = var.name_prefix
  kms_key_arn             = module.kms.key_arn
  recovery_window_in_days = 0
}

# The SES identity and configuration set the api and worker send through with
# MAIL_BACKEND=ses (the Floci overlay's default).
module "email" {
  source       = "../../modules/email"
  name_prefix  = var.name_prefix
  domain       = var.mail_domain
  from_address = var.mail_from_address
}
