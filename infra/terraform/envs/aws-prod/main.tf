# ─────────────────────────────────────────────────────────────────────────────
# aws-prod: production. Three AZs, NAT per AZ, Multi-AZ database, primary plus
# replica cache with automatic failover, deletion protection, interface endpoints,
# 365-day log retention, audit checkpoints locked in COMPLIANCE mode for a year.
#
# Validate-only in this repository (nothing is ever applied to a real account by
# the project itself); everything needed to deploy is here:
#   cp terraform.tfvars.example terraform.tfvars   # then edit
#   make aws-deploy ENV=aws-prod TAG=0.1.0   # registries, images, infrastructure,
#                                           # migrations, then the services
# ─────────────────────────────────────────────────────────────────────────────

module "kms" {
  source                  = "../../modules/kms"
  name_prefix             = var.name_prefix
  deletion_window_in_days = 30
}

module "network" {
  source                     = "../../modules/network"
  name_prefix                = var.name_prefix
  az_count                   = 3
  single_nat_gateway         = false
  enable_interface_endpoints = true
  logs_kms_key_arn           = module.kms.key_arn
  flow_log_retention_days    = 365
}

module "database" {
  source                = "../../modules/database"
  name_prefix           = var.name_prefix
  vpc_id                = module.network.vpc_id
  subnet_ids            = module.network.private_subnet_ids
  kms_key_arn           = module.kms.key_arn
  instance_class        = var.db_instance_class
  allocated_storage     = 50
  max_allocated_storage = 500
  multi_az              = true
  backup_retention_days = 14
  deletion_protection   = true
  skip_final_snapshot   = false
}

module "cache" {
  source                  = "../../modules/cache"
  name_prefix             = var.name_prefix
  vpc_id                  = module.network.vpc_id
  subnet_ids              = module.network.private_subnet_ids
  kms_key_arn             = module.kms.key_arn
  logs_kms_key_arn        = module.kms.key_arn
  node_type               = var.cache_node_type
  num_cache_clusters      = 2
  snapshot_retention_days = 7
  recovery_window_in_days = 30
  log_retention_days      = 365
  apply_immediately       = false
}

module "storage" {
  source                = "../../modules/storage"
  name_prefix           = var.name_prefix
  kms_key_arn           = module.kms.key_arn
  backup_retention_days = var.backup_retention_days
  force_destroy         = false
  audit_lock_mode       = "COMPLIANCE"
  audit_retention_days  = var.audit_retention_days
}

module "secrets" {
  source                  = "../../modules/secrets"
  name_prefix             = var.name_prefix
  kms_key_arn             = module.kms.key_arn
  recovery_window_in_days = 30
  include_connection_urls = true
  database_url            = module.database.connection_url
  redis_url               = module.cache.connection_url
}

module "ecr" {
  source       = "../../modules/ecr"
  name_prefix  = var.name_prefix
  kms_key_arn  = module.kms.key_arn
  force_delete = false
}

module "email" {
  source          = "../../modules/email"
  name_prefix     = var.name_prefix
  domain          = var.mail_domain
  from_address    = var.mail_from_address
  route53_zone_id = var.route53_zone_id
}

locals {
  url = "https://${var.hostname}"

  # Everything the api, worker, egress and migrate read that is not a secret. Secrets
  # (SESSION_SECRET, TOKEN_PEPPER, SANDBOX_TOKEN, DATABASE_URL, REDIS_URL, VAULT_TOKEN)
  # come from module.secrets; PORT, PUBLIC_URL, PUBLIC_API_URL,
  # OBJECTS_BUCKET, AUDIT_BUCKET, EGRESS_URL, EGRESS_LISTEN_PORT, SANDBOX_URL and
  # HTTP_KEEP_ALIVE_S from module.service.
  api_environment = merge({
    ENVIRONMENT       = "production"
    AGENTGUARD_CLOUD  = "aws"
    LOG_LEVEL         = "INFO"
    AWS_REGION        = var.region
    KEY_MODE          = "kms"
    KMS_KEY_ID        = module.kms.alias_name
    STORAGE           = "s3"
    CORS_ORIGINS      = local.url
    COOKIE_SECURE     = "true"
    SIGNUP_ENABLED    = tostring(var.signup_enabled)
    MAIL_BACKEND      = "ses"
    MAIL_FROM_NAME    = var.mail_from_name
    MAIL_FROM_ADDRESS = var.mail_from_address
    # External secret stores an organisation may choose: AWS Secrets Manager (this
    # account, through the task role) and an optional Vault (VAULT_TOKEN in the
    # integrations secret).
    AWS_SECRETS_ENABLED = "true"
    VAULT_URL           = var.vault_url
    OPA_URL             = var.opa_url
    TOKENSHIELD_URL     = var.tokenshield_url
    # HTTP tools, MCP servers and webhooks must be public addresses in production (SSRF);
    # a self-hosted classifier inside the VPC is opted in with ai_egress plus this flag.
    ALLOW_PRIVATE_URLS         = "false"
    AI_ALLOW_PRIVATE_ENDPOINTS = length(var.ai_egress) > 0 ? "true" : "false"
    # Trust X-Forwarded-For only from inside the VPC (the load balancer).
    FORWARDED_ALLOW_IPS = module.network.vpc_cidr_block
    # Pool sized so (api_max + worker_max + egress_max + migrate) x (pool + overflow)
    # stays under db_max_connections.
    DB_POOL_SIZE    = "10"
    DB_MAX_OVERFLOW = "10"
  }, var.api_extra_environment)
}

module "service" {
  source             = "../../modules/service"
  name_prefix        = var.name_prefix
  vpc_id             = module.network.vpc_id
  public_subnet_ids  = module.network.public_subnet_ids
  private_subnet_ids = module.network.private_subnet_ids
  hostname           = var.hostname
  certificate_arn    = var.certificate_arn
  route53_zone_id    = var.route53_zone_id

  server_image  = "${module.ecr.repository_urls["server"]}:${var.image_tag}"
  web_image     = "${module.ecr.repository_urls["web"]}:${var.image_tag}"
  migrate_image = "${module.ecr.repository_urls["server"]}:${coalesce(var.migrate_image_tag, var.image_tag)}"

  environment      = local.api_environment
  secrets          = module.secrets.ecs_secrets
  migrate_secrets  = module.secrets.bootstrap_secrets
  send_mail        = true
  mail_policy_json = module.email.send_policy_json
  sandbox_url      = module.sandbox.url

  kms_key_arn             = module.kms.key_arn
  objects_bucket_arn      = module.storage.bucket_arn
  objects_bucket_name     = module.storage.bucket_name
  audit_bucket_arn        = module.storage.audit_bucket_arn
  audit_bucket_name       = module.storage.audit_bucket_name
  db_security_group_id    = module.database.security_group_id
  db_port                 = module.database.port
  cache_security_group_id = module.cache.security_group_id
  log_group_names         = module.observability.log_group_names
  logs_kms_key_arn        = module.kms.key_arn

  api_cpu          = 1024
  api_memory       = 2048
  api_min_count    = 2
  api_max_count    = 6
  worker_cpu       = 1024
  worker_memory    = 2048
  worker_min_count = 2
  worker_max_count = 6
  egress_min_count = 2
  egress_max_count = 6
  web_min_count    = 2
  web_max_count    = 4

  egress_client_cidrs              = var.egress_client_cidrs
  egress_client_security_group_ids = var.egress_client_security_group_ids
  egress_extra_ports               = var.egress_extra_ports

  deletion_protection    = true
  enable_waf             = true
  waf_log_retention_days = 365
  metrics_allowed_cidrs  = var.metrics_allowed_cidrs
  worker_metrics_cidrs   = var.worker_metrics_cidrs
  ai_egress              = var.ai_egress
}

module "sandbox" {
  source                    = "../../modules/sandbox"
  name_prefix               = var.name_prefix
  vpc_id                    = module.network.vpc_id
  vpc_cidr_block            = module.network.vpc_cidr_block
  private_subnet_ids        = module.network.private_subnet_ids
  namespace_id              = module.service.namespace_id
  namespace_name            = module.service.namespace_name
  image                     = "${module.ecr.repository_urls["sandbox"]}:${var.image_tag}"
  caller_security_group_ids = { api = module.service.security_group_ids["api"], worker = module.service.security_group_ids["worker"] }
  egress_security_group_id  = module.service.security_group_ids["egress"]
  egress_port               = module.service.egress_port
  secrets                   = module.secrets.sandbox_secrets
  kms_key_arn               = module.kms.key_arn
  log_group_name            = module.observability.log_group_names["sandbox"]
  seccomp_profile_json      = file("${path.module}/../../../docker/sandbox-seccomp.json")
  instance_type             = var.sandbox_instance_type
  ami_id                    = var.sandbox_ami_id
  environment               = var.sandbox_extra_environment
  min_instances             = 2
  max_instances             = 6
  min_tasks                 = 2
  max_tasks                 = 12
}

module "observability" {
  source             = "../../modules/observability"
  name_prefix        = var.name_prefix
  log_retention_days = 365
  logs_kms_key_arn   = module.kms.key_arn
  sns_kms_key_arn    = module.kms.key_arn
  alarm_email        = var.alarm_email

  alb_arn_suffix   = module.service.alb_arn_suffix
  ecs_cluster_name = module.service.cluster_name
  lb_services      = module.service.services
  ecs_services     = module.service.service_names

  db_instance_identifier     = module.database.instance_identifier
  db_max_connections         = 400
  cache_replication_group_id = module.cache.replication_group_id
  cache_node_count           = 2

  sandbox_cluster_name = module.sandbox.cluster_name
  sandbox_service_name = module.sandbox.service_name
}
