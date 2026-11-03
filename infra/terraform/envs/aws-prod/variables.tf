variable "region" {
  description = "AWS region."
  type        = string
}

variable "environment" {
  description = "Environment tag."
  type        = string
  default     = "prod"
}

variable "extra_tags" {
  description = "Tags added to every resource."
  type        = map(string)
  default     = {}
}

variable "name_prefix" {
  description = "Prefix for every resource name (at most 24 characters); the bucket names derive from it, so make it globally unique (e.g. \"acme-agentguard-prod\")."
  type        = string
}

variable "hostname" {
  description = "Public host name of the dashboard and API, e.g. agentguard.example.com."
  type        = string
}

variable "certificate_arn" {
  description = "ACM certificate in the same region covering hostname."
  type        = string
}

variable "route53_zone_id" {
  description = "Hosted zone for the alias record and the DKIM records. Null: create them yourself (load_balancer_dns_name and dkim_records outputs)."
  type        = string
  default     = null
}

variable "mail_domain" {
  description = "Domain approval and incident mail is sent from (an SES domain identity), e.g. agentguard.example.com."
  type        = string
}

variable "mail_from_address" {
  description = "From address of AgentGuard mail, on mail_domain (MAIL_FROM_ADDRESS), e.g. agentguard@agentguard.example.com."
  type        = string
}

variable "mail_from_name" {
  description = "Display name on outgoing mail (MAIL_FROM_NAME)."
  type        = string
  default     = "AgentGuard"
}

variable "signup_enabled" {
  description = "Let anyone create an organisation from the sign-up page (SIGNUP_ENABLED). Turn off once your organisation exists; invitations and OIDC still work."
  type        = bool
  default     = false
}

variable "image_tag" {
  description = "Image tag the services run (the git commit or a release); the same tag for server, web and sandbox."
  type        = string
}

variable "migrate_image_tag" {
  description = "Image tag of the one-off migrate task. Null: image_tag. scripts/aws-deploy.sh sets it to the new release while the services stay on the old one, migrates, then moves the services."
  type        = string
  default     = null
}

variable "alarm_email" {
  description = "Alarm notification address."
  type        = string
  default     = null
}

variable "api_extra_environment" {
  description = "Extra api, worker, egress and migrate environment (see docs/guides/configuration.md). Never secrets."
  type        = map(string)
  default     = {}
}

variable "sandbox_extra_environment" {
  description = "Extra sandbox environment (SANDBOX_* settings). Never secrets."
  type        = map(string)
  default     = {}
}

variable "backup_retention_days" {
  description = "Days a database backup in the objects bucket (backups/) is kept."
  type        = number
  default     = 35
}

variable "audit_retention_days" {
  description = "Days every signed audit checkpoint stays under Object Lock (COMPLIANCE)."
  type        = number
  default     = 365
}

variable "db_instance_class" {
  description = "RDS instance class."
  type        = string
  default     = "db.t4g.medium"
}

variable "cache_node_type" {
  description = "ElastiCache node type."
  type        = string
  default     = "cache.t4g.small"
}

variable "sandbox_instance_type" {
  description = "ARM64 instance type of the sandbox hosts."
  type        = string
  default     = "c7g.large"
}

variable "sandbox_ami_id" {
  description = "Sandbox host AMI. Null: the latest ECS-optimized Amazon Linux 2023 ARM64 AMI."
  type        = string
  default     = null
}

variable "vault_url" {
  description = "HTTPS URL of an existing HashiCorp Vault for the Vault secret store (VAULT_URL). Empty: Vault is not offered. Put its token in the integrations secret."
  type        = string
  default     = ""
}

variable "opa_url" {
  description = "URL of an Open Policy Agent your organisation runs (OPA_URL). Empty: native policies only."
  type        = string
  default     = ""
}

variable "tokenshield_url" {
  description = "URL of a TokenShield for token and spend budgets (TOKENSHIELD_URL). Empty: local limits only. Put its API key in the integrations secret."
  type        = string
  default     = ""
}

variable "egress_client_cidrs" {
  description = "CIDRs of the agent workloads allowed to send traffic through the egress proxy (egress.<name_prefix>.internal:3128)."
  type        = list(string)
  default     = []
}

variable "egress_client_security_group_ids" {
  description = "Security groups of agent workloads in this VPC allowed to use the egress proxy."
  type        = list(string)
  default     = []
}

variable "egress_extra_ports" {
  description = "Destination ports beyond 443 and 80 the egress proxy may connect to (network policy still decides)."
  type        = list(number)
  default     = []
}

variable "metrics_allowed_cidrs" {
  description = "Source CIDRs allowed to scrape the api's /metrics through the load balancer."
  type        = list(string)
  default     = []
}

variable "worker_metrics_cidrs" {
  description = "In-VPC Prometheus CIDRs allowed to scrape the worker's /metrics on port 9464. Empty: no worker ingress."
  type        = list(string)
  default     = []
}

variable "ai_egress" {
  description = "Extra api and worker egress for a self-hosted classifier model not on HTTPS 443 (Ollama, vLLM), as { cidr, port } pairs. Also allows private AI endpoints."
  type = list(object({
    cidr = string
    port = number
  }))
  default = []
}
