# The AgentGuard control plane on ECS Fargate, behind one Application Load Balancer:
#
#   api      management API (/api/*), token exchange (/oauth/*), JWKS (/.well-known/*), the
#            decision API, the MCP gateway (/mcp), the live feed (/ws/*), probes and docs.
#            ALB on hostname, autoscaled.
#   worker   notifications, approval expiry, execution on approval, MCP discovery and
#            health, behavioural analysis, auto-response, audit checkpoints, retention
#            (jobs claimed from Postgres with leases). No ingress, except Prometheus on
#            WORKER_METRICS_PORT. Autoscaled.
#   egress   the egress forward proxy (HTTP and CONNECT) on EGRESS_LISTEN_PORT. Never on
#            the load balancer: reachable inside the VPC as egress.<name_prefix>.internal
#            (Cloud Map), only from the api, the worker, the sandbox (sandbox module) and
#            the agent networks listed in egress_client_cidrs and
#            egress_client_security_group_ids. Autoscaled.
#   web      Next.js dashboard. ALB, every other path, autoscaled.
#   migrate  one-off task definition (no service) for `agentguard migrate`, and with a
#            command override for `create-admin` and `seed-demo`. It may run a newer image
#            than the services (migrate_image), so a deploy migrates before it rolls.
#
# The web task reaches the api through Cloud Map private DNS (api.<name_prefix>.internal)
# for its server-side rewrites. Browsers, SDKs and MCP clients reach the api through the
# load balancer, which routes the api's paths before they get to web.
#
# WebSockets: the load balancer's idle timeout (idle_timeout, 300 s by default) bounds a
# quiet socket; the api sends pings well inside it, and its HTTP keep-alive
# (HTTP_KEEP_ALIVE_S) is set above it so the load balancer, not the task, always closes
# an idle connection first (otherwise a reused connection can answer 502).
#
# Every app gets the same hardened shape:
#
#   - its own security group: ingress only from the load balancer or the named callers,
#     egress only to HTTPS and, when it needs them, PostgreSQL, Redis and its callees
#     (the egress proxy also reaches plain HTTP and egress_extra_ports, because enforcing
#     network policy on those destinations is its job)
#   - its own execution role (pull, log, inject exactly its secrets) and task role (api,
#     worker, migrate: the two buckets and the KMS key, and SES for mail; egress and web:
#     none)
#   - a read-only root filesystem with only /tmp (and Next's cache for web) writable,
#     ARM64, no public IP, deployment circuit breaker with automatic rollback
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  region      = data.aws_region.current.region
  namespace   = "${var.name_prefix}.internal"
  port        = var.container_port
  egress_port = var.egress_port

  probe      = "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:%s/%s', timeout=3).status == 200 else 1)"
  tcp_probe  = "import socket; socket.create_connection(('127.0.0.1', %s), timeout=3).close()"
  web_health = ["CMD", "node", "-e", "fetch('http://127.0.0.1:${local.port}/api/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]

  internal_url = {
    api    = "http://api.${local.namespace}:${local.port}"
    egress = "http://egress.${local.namespace}:${local.egress_port}"
  }
  public_url = "https://${var.hostname}"

  # One map drives security groups, roles, task definitions and services. The server
  # image carries the `agentguard` CLI as its entrypoint, so commands are subcommands.
  # env: which environment and secrets the container gets (control, migrate, web).
  apps = {
    api = {
      image          = var.server_image, command = ["serve", "--host", "0.0.0.0", "--port", tostring(local.port)], port = local.port
      service        = true, public = true, discover = true, env = "control", objects = true, database = true, cache = true
      cpu            = var.api_cpu, memory = var.api_memory, min_count = var.api_min_count, max_count = var.api_max_count
      health         = ["CMD", "python", "-c", format(local.probe, local.port, "healthz")], start_period = 60
      writable_paths = ["/tmp"], stop_timeout = 45, ai = true
    }
    worker = {
      image          = var.server_image, command = ["worker"], port = var.worker_metrics_port
      service        = true, public = false, discover = false, env = "control", objects = true, database = true, cache = true
      cpu            = var.worker_cpu, memory = var.worker_memory, min_count = var.worker_min_count, max_count = var.worker_max_count
      health         = ["CMD", "python", "-c", format(local.probe, var.worker_metrics_port, "metrics")], start_period = 60
      writable_paths = ["/tmp"], stop_timeout = 120, ai = true
    }
    egress = {
      image          = var.server_image, command = ["egress"], port = local.egress_port
      service        = true, public = false, discover = true, env = "control", objects = false, database = true, cache = true
      cpu            = var.egress_cpu, memory = var.egress_memory, min_count = var.egress_min_count, max_count = var.egress_max_count
      health         = ["CMD", "python", "-c", format(local.tcp_probe, local.egress_port)], start_period = 30
      writable_paths = ["/tmp"], stop_timeout = 60, ai = false
    }
    web = {
      image          = var.web_image, command = null, port = local.port
      service        = true, public = true, discover = false, env = "web", objects = false, database = false, cache = false
      cpu            = var.web_cpu, memory = var.web_memory, min_count = var.web_min_count, max_count = var.web_max_count
      health         = local.web_health, start_period = 30
      writable_paths = ["/tmp", "/app/.next/cache"], stop_timeout = 45, ai = false
    }
    migrate = {
      image          = coalesce(var.migrate_image, var.server_image), command = ["migrate"], port = local.port
      service        = false, public = false, discover = false, env = "migrate", objects = true, database = true, cache = true
      cpu            = 512, memory = 1024, min_count = 0, max_count = 0
      health         = null, start_period = 0
      writable_paths = ["/tmp"], stop_timeout = 45, ai = false
    }
  }

  services      = { for k, a in local.apps : k => a if a.service }
  load_balanced = { for k, a in local.apps : k => a if a.public }
  discovered    = { for k, a in local.apps : k => a if a.discover }
  with_database = { for k, a in local.apps : k => a if a.database }
  with_cache    = { for k, a in local.apps : k => a if a.cache }
  with_objects  = { for k, a in local.apps : k => a if a.objects }
  scaled        = { for k, a in local.services : k => a if a.max_count > a.min_count }

  # Who calls whom inside the VPC, on the callee's port. The api and the worker send their
  # own outbound calls (HTTP tools, MCP upstreams, webhooks) through the egress proxy.
  internal_calls = {
    "web-api"       = { from = "web", to = "api" }
    "api-egress"    = { from = "api", to = "egress" }
    "worker-egress" = { from = "worker", to = "egress" }
  }

  control_environment = merge({
    PORT           = tostring(local.port)
    PUBLIC_URL     = local.public_url
    PUBLIC_API_URL = local.public_url
    OBJECTS_BUCKET = var.objects_bucket_name
    AUDIT_BUCKET   = var.audit_bucket_name
    EGRESS_URL     = local.internal_url["egress"]
    # The egress task listens here; the others ignore it.
    EGRESS_LISTEN_PORT = tostring(local.egress_port)
    SANDBOX_URL        = var.sandbox_url
    # Above the load balancer's idle timeout, so the load balancer closes idle
    # connections first (see the header).
    HTTP_KEEP_ALIVE_S   = tostring(var.idle_timeout + 10)
    WORKER_METRICS_PORT = tostring(var.worker_metrics_port)
  }, var.environment)
  environment = {
    control = local.control_environment
    migrate = local.control_environment
    web = merge({
      PORT     = tostring(local.port)
      HOSTNAME = "0.0.0.0"
      # Server-side rewrites only; browsers reach the api through the load balancer.
      API_URL          = local.internal_url["api"]
      API_INTERNAL_URL = local.internal_url["api"]
    }, var.web_environment)
  }
  secrets = {
    control = var.secrets
    # The one-off task also gets the bootstrap secret (create-admin reads the first
    # owner's password from it, so it never travels as a task override).
    migrate = concat(var.secrets, var.migrate_secrets)
    web     = []
  }
  with_secrets = { for k, a in local.apps : k => a if length(local.secrets[a.env]) > 0 }
  secret_arns = {
    for k, a in local.with_secrets : k => distinct([
      for s in local.secrets[a.env] : regex("^(arn:[^:]+:secretsmanager:[^:]+:[^:]+:secret:[^:]+)", s.valueFrom)[0]
    ])
  }

  # Paths the api serves, in groups of at most five (the ALB limit per condition).
  # /metrics is handled by its own rules below. /api/healthz is the web server's own
  # probe, so it is claimed for web first.
  api_paths = {
    100 = ["/api/*", "/ws/*", "/healthz", "/readyz"]
    101 = ["/oauth/*", "/.well-known/*", "/mcp", "/mcp/*"]
    102 = ["/docs", "/docs/*", "/openapi.json"]
  }
  ai_apps = { for k, a in local.apps : k => a if a.ai }
}

# ─── Cluster ─────────────────────────────────────────────────────────────────

resource "aws_ecs_cluster" "this" {
  name = var.name_prefix
  setting {
    name  = "containerInsights"
    value = var.container_insights
  }
}

resource "aws_ecs_cluster_capacity_providers" "this" {
  cluster_name       = aws_ecs_cluster.this.name
  capacity_providers = ["FARGATE"]
  default_capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
  }
}

# ─── Service discovery ───────────────────────────────────────────────────────

resource "aws_service_discovery_private_dns_namespace" "this" {
  name        = local.namespace
  description = "AgentGuard service to service names"
  vpc         = var.vpc_id
}

resource "aws_service_discovery_service" "this" {
  for_each = local.discovered
  name     = each.key
  dns_config {
    namespace_id   = aws_service_discovery_private_dns_namespace.this.id
    routing_policy = "MULTIVALUE"
    dns_records {
      type = "A"
      ttl  = 10
    }
  }
  # ECS reports task health; unhealthy tasks leave DNS without a Route53 health check.
  health_check_custom_config {}
}

# ─── Load balancer ───────────────────────────────────────────────────────────

resource "aws_security_group" "alb" {
  name        = "${var.name_prefix}-alb"
  description = "HTTPS into the load balancer"
  vpc_id      = var.vpc_id
  tags        = { Name = "${var.name_prefix}-alb" }
}

resource "aws_vpc_security_group_ingress_rule" "alb_public" {
  #checkov:skip=CKV_AWS_260:Port 80 only answers with a 301 to HTTPS (see the http listener).
  for_each          = toset(["80", "443"])
  security_group_id = aws_security_group.alb.id
  description       = "HTTP/HTTPS from the internet (80 only redirects)"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = tonumber(each.key)
  to_port           = tonumber(each.key)
}

resource "aws_lb" "this" {
  #checkov:skip=CKV_AWS_150:Deletion protection is an input (deletion_protection); aws-prod enables it.
  #checkov:skip=CKV2_AWS_28:A WAF web ACL is attached below when enable_waf is true (both AWS environments).
  #checkov:skip=CKV2_AWS_76:The web ACL below includes AWSManagedRulesKnownBadInputsRuleSet (Log4JRCE, verified by CKV_AWS_192); this graph check cannot follow the enable_waf-gated association.
  #checkov:skip=CKV_AWS_91:Access logging is opt-in via access_logs_bucket (the bucket needs an ELB log-delivery policy the operator owns).
  name                       = "${var.name_prefix}-alb"
  load_balancer_type         = "application"
  internal                   = false
  subnets                    = var.public_subnet_ids
  security_groups            = [aws_security_group.alb.id]
  drop_invalid_header_fields = true
  # WebSockets (the live decision feed) stay open while idle up to this; the api pings
  # inside it, so it only reaps connections a client abandoned without closing.
  idle_timeout               = var.idle_timeout
  enable_deletion_protection = var.deletion_protection

  dynamic "access_logs" {
    for_each = var.access_logs_bucket == null ? [] : [1]
    content {
      bucket  = var.access_logs_bucket
      prefix  = "alb"
      enabled = true
    }
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_target_group" "this" {
  #checkov:skip=CKV_AWS_378:TLS terminates at the load balancer; the hop to the task stays inside private subnets.
  for_each             = local.load_balanced
  name                 = substr("${var.name_prefix}-${each.key}", 0, 32)
  port                 = local.port
  protocol             = "HTTP"
  target_type          = "ip"
  vpc_id               = var.vpc_id
  deregistration_delay = 30
  health_check {
    # Liveness, not readiness: a Redis blip must not pull every task out of the load
    # balancer (Redis only carries live fan-out and caches; jobs live in Postgres).
    path                = each.key == "web" ? "/api/healthz" : "/healthz"
    matcher             = "200-399"
    interval            = 15
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

# Everything not claimed by a rule below is the web app.
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this["web"].arn
  }
}

resource "aws_lb_listener_rule" "api" {
  for_each     = local.api_paths
  listener_arn = aws_lb_listener.https.arn
  priority     = tonumber(each.key)
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this["api"].arn
  }
  condition {
    path_pattern {
      values = each.value
    }
  }
}

# The web server's own probe lives under /api, so it is routed before the api's /api/*.
resource "aws_lb_listener_rule" "web_health" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 30
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this["web"].arn
  }
  condition {
    path_pattern {
      values = ["/api/healthz"]
    }
  }
}

# Prometheus metrics reach the api only from the listed scrapers. Everyone else gets a 404
# from the load balancer itself.
resource "aws_lb_listener_rule" "metrics_allowed" {
  count        = length(var.metrics_allowed_cidrs) > 0 ? 1 : 0
  listener_arn = aws_lb_listener.https.arn
  priority     = 10
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this["api"].arn
  }
  condition {
    path_pattern {
      values = ["/metrics"]
    }
  }
  condition {
    source_ip {
      values = var.metrics_allowed_cidrs
    }
  }
}

resource "aws_lb_listener_rule" "metrics_denied" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 20
  action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "Not found"
      status_code  = "404"
    }
  }
  condition {
    path_pattern {
      values = ["/metrics"]
    }
  }
}

resource "aws_route53_record" "this" {
  count   = var.route53_zone_id == null ? 0 : 1
  zone_id = var.route53_zone_id
  name    = var.hostname
  type    = "A"
  alias {
    name                   = aws_lb.this.dns_name
    zone_id                = aws_lb.this.zone_id
    evaluate_target_health = true
  }
}

# ─── WAF ─────────────────────────────────────────────────────────────────────

# Managed rules with one deliberate exception: code submitted for the sandbox, tool
# parameters, MCP tool outputs relayed for scanning and policy YAML all look like attacks
# to the body-inspecting rules of the common rule set (bodies above 8 KB, script tags,
# path traversal), and inspecting hostile content is AgentGuard's own job, so those only
# count. The api's body size limits, rate limits and its own validation and scanners are
# the controls that understand a request.
resource "aws_wafv2_web_acl" "this" {
  count = var.enable_waf ? 1 : 0
  name  = "${var.name_prefix}-alb"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "common"
    priority = 10
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesCommonRuleSet"
        dynamic "rule_action_override" {
          for_each = toset(["SizeRestrictions_BODY", "CrossSiteScripting_BODY", "GenericLFI_BODY", "GenericRFI_BODY"])
          content {
            name = rule_action_override.value
            action_to_use {
              count {}
            }
          }
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name_prefix}-common"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "known-bad-inputs"
    priority = 20
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name_prefix}-known-bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "ip-reputation"
    priority = 30
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesAmazonIpReputationList"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name_prefix}-ip-reputation"
      sampled_requests_enabled   = true
    }
  }

  # A coarse flood guard per source IP. The api's own per-visitor and per-key limits are
  # the real ones; this only keeps a flood off the tasks. Offices share one address.
  rule {
    name     = "rate-per-ip"
    priority = 40
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit              = var.waf_rate_limit_per_5min
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name_prefix}-rate-per-ip"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name_prefix}-alb"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "this" {
  count        = var.enable_waf ? 1 : 0
  resource_arn = aws_lb.this.arn
  web_acl_arn  = aws_wafv2_web_acl.this[0].arn
}

resource "aws_cloudwatch_log_group" "waf" {
  #checkov:skip=CKV_AWS_338:Retention is an input (waf_log_retention_days); aws-prod keeps 365 days.
  count             = var.enable_waf ? 1 : 0
  name              = "aws-waf-logs-${var.name_prefix}"
  retention_in_days = var.waf_log_retention_days
  kms_key_id        = var.logs_kms_key_arn
}

resource "aws_wafv2_web_acl_logging_configuration" "this" {
  count                   = var.enable_waf ? 1 : 0
  resource_arn            = aws_wafv2_web_acl.this[0].arn
  log_destination_configs = [aws_cloudwatch_log_group.waf[0].arn]
  # Sessions, API keys, agent tokens, CSRF tokens and token links (?token=, WebSocket
  # tokens) never reach a log.
  redacted_fields {
    single_header {
      name = "authorization"
    }
  }
  redacted_fields {
    single_header {
      name = "cookie"
    }
  }
  redacted_fields {
    single_header {
      name = "x-api-key"
    }
  }
  redacted_fields {
    single_header {
      name = "x-agentguard-csrf"
    }
  }
  redacted_fields {
    query_string {}
  }
}

# ─── Task networking ─────────────────────────────────────────────────────────

resource "aws_security_group" "task" {
  for_each    = local.apps
  name        = "${var.name_prefix}-${each.key}-task"
  description = "${each.key} tasks; ingress only from the load balancer or named callers, if at all"
  vpc_id      = var.vpc_id
  tags        = { Name = "${var.name_prefix}-${each.key}-task" }
}

resource "aws_vpc_security_group_ingress_rule" "from_lb" {
  for_each                     = local.load_balanced
  security_group_id            = aws_security_group.task[each.key].id
  description                  = "From the load balancer"
  referenced_security_group_id = aws_security_group.alb.id
  ip_protocol                  = "tcp"
  from_port                    = local.port
  to_port                      = local.port
}

resource "aws_vpc_security_group_egress_rule" "lb_to_task" {
  for_each                     = local.load_balanced
  security_group_id            = aws_security_group.alb.id
  description                  = "To ${each.key} tasks"
  referenced_security_group_id = aws_security_group.task[each.key].id
  ip_protocol                  = "tcp"
  from_port                    = local.port
  to_port                      = local.port
}

resource "aws_vpc_security_group_ingress_rule" "internal" {
  for_each                     = local.internal_calls
  security_group_id            = aws_security_group.task[each.value.to].id
  description                  = "From ${each.value.from} tasks"
  referenced_security_group_id = aws_security_group.task[each.value.from].id
  ip_protocol                  = "tcp"
  from_port                    = local.apps[each.value.to].port
  to_port                      = local.apps[each.value.to].port
}

resource "aws_vpc_security_group_egress_rule" "internal" {
  for_each                     = local.internal_calls
  security_group_id            = aws_security_group.task[each.value.from].id
  description                  = "To ${each.value.to} tasks"
  referenced_security_group_id = aws_security_group.task[each.value.to].id
  ip_protocol                  = "tcp"
  from_port                    = local.apps[each.value.to].port
  to_port                      = local.apps[each.value.to].port
}

# Agents outside AgentGuard (your workloads) send their outbound traffic through the
# egress proxy: by CIDR, by security group, or both. The sandbox's rule is in the sandbox
# module. Nobody else can open a connection to it.
resource "aws_vpc_security_group_ingress_rule" "egress_clients_cidr" {
  for_each          = toset(var.egress_client_cidrs)
  security_group_id = aws_security_group.task["egress"].id
  description       = "Agents in ${each.value} to the egress proxy"
  cidr_ipv4         = each.value
  ip_protocol       = "tcp"
  from_port         = local.egress_port
  to_port           = local.egress_port
}

resource "aws_vpc_security_group_ingress_rule" "egress_clients_sg" {
  for_each                     = toset(var.egress_client_security_group_ids)
  security_group_id            = aws_security_group.task["egress"].id
  description                  = "Agents in ${each.value} to the egress proxy"
  referenced_security_group_id = each.value
  ip_protocol                  = "tcp"
  from_port                    = local.egress_port
  to_port                      = local.egress_port
}

# The proxy forwards what network policy allows, so it reaches plain HTTP and any extra
# destination ports the operator lists; HTTPS is open for every app below.
resource "aws_vpc_security_group_egress_rule" "egress_destinations" {
  for_each          = toset([for p in concat([80], var.egress_extra_ports) : tostring(p)])
  security_group_id = aws_security_group.task["egress"].id
  description       = "Egress proxy to destinations on port ${each.value} (network policy decides which)"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = tonumber(each.value)
  to_port           = tonumber(each.value)
}

# The worker has no load balancer; an in-VPC Prometheus scrapes its /metrics directly.
resource "aws_vpc_security_group_ingress_rule" "worker_metrics" {
  for_each          = toset(var.worker_metrics_cidrs)
  security_group_id = aws_security_group.task["worker"].id
  description       = "Prometheus scrape of worker /metrics"
  cidr_ipv4         = each.value
  ip_protocol       = "tcp"
  from_port         = var.worker_metrics_port
  to_port           = var.worker_metrics_port
}

resource "aws_vpc_security_group_egress_rule" "https" {
  for_each          = local.apps
  security_group_id = aws_security_group.task[each.key].id
  description       = "HTTPS to AWS APIs, ECR, OIDC providers, AI classifiers and policy-approved destinations"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

# A self-hosted classifier model on another port (Ollama on 11434, vLLM on 8000 inside the
# VPC), for the api (inline injection checks) and the worker (behavioural analysis): opt in
# per port and destination; nothing beyond HTTPS is open by default.
resource "aws_vpc_security_group_egress_rule" "ai" {
  for_each = merge([
    for app in keys(local.ai_apps) : { for e in var.ai_egress : "${app}:${e.cidr}:${e.port}" => merge(e, { app = app }) }
  ]...)
  security_group_id = aws_security_group.task[each.value.app].id
  description       = "Self-hosted model on port ${each.value.port}"
  cidr_ipv4         = each.value.cidr
  ip_protocol       = "tcp"
  from_port         = each.value.port
  to_port           = each.value.port
}

resource "aws_vpc_security_group_egress_rule" "db" {
  for_each                     = local.with_database
  security_group_id            = aws_security_group.task[each.key].id
  description                  = "To PostgreSQL"
  referenced_security_group_id = var.db_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = var.db_port
  to_port                      = var.db_port
}

resource "aws_vpc_security_group_ingress_rule" "db_from_task" {
  for_each                     = local.with_database
  security_group_id            = var.db_security_group_id
  description                  = "From ${each.key} tasks"
  referenced_security_group_id = aws_security_group.task[each.key].id
  ip_protocol                  = "tcp"
  from_port                    = var.db_port
  to_port                      = var.db_port
}

resource "aws_vpc_security_group_egress_rule" "cache" {
  for_each                     = local.with_cache
  security_group_id            = aws_security_group.task[each.key].id
  description                  = "To Redis/Valkey"
  referenced_security_group_id = var.cache_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = var.cache_port
  to_port                      = var.cache_port
}

resource "aws_vpc_security_group_ingress_rule" "cache_from_task" {
  for_each                     = local.with_cache
  security_group_id            = var.cache_security_group_id
  description                  = "From ${each.key} tasks"
  referenced_security_group_id = aws_security_group.task[each.key].id
  ip_protocol                  = "tcp"
  from_port                    = var.cache_port
  to_port                      = var.cache_port
}

# ─── IAM ─────────────────────────────────────────────────────────────────────

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

# Execution role: pull the image, write logs, inject this app's secrets. Nothing else.
resource "aws_iam_role" "execution" {
  for_each           = local.apps
  name               = "${var.name_prefix}-${each.key}-execution"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy_attachment" "execution" {
  for_each   = local.apps
  role       = aws_iam_role.execution[each.key].name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

data "aws_iam_policy_document" "execution" {
  for_each = local.with_secrets
  statement {
    sid       = "InjectSecrets"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = local.secret_arns[each.key]
  }
  statement {
    sid       = "DecryptSecrets"
    actions   = ["kms:Decrypt"]
    resources = [var.kms_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${local.region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "execution" {
  for_each = local.with_secrets
  name     = "secrets"
  role     = aws_iam_role.execution[each.key].id
  policy   = data.aws_iam_policy_document.execution[each.key].json
}

# Task role: exactly what the api, worker and CLI code does while running. The web and
# egress tasks call no AWS API, so their task roles have no policy at all.
data "aws_iam_policy_document" "objects" {
  # Incident evidence, exports and backups.
  statement {
    sid       = "Objects"
    actions   = ["s3:PutObject", "s3:GetObject", "s3:DeleteObject"]
    resources = ["${var.objects_bucket_arn}/*"]
  }
  # Without ListBucket a missing object answers 403 instead of 404.
  statement {
    sid       = "ObjectsBucket"
    actions   = ["s3:ListBucket"]
    resources = [var.objects_bucket_arn]
  }
  # Signed audit checkpoints: write and read, never delete (the bucket's Object Lock would
  # refuse it anyway inside the retention window).
  statement {
    sid       = "AuditCheckpoints"
    actions   = ["s3:PutObject", "s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectRetention"]
    resources = ["${var.audit_bucket_arn}/*"]
  }
  statement {
    sid       = "AuditBucket"
    actions   = ["s3:ListBucket", "s3:ListBucketVersions"]
    resources = [var.audit_bucket_arn]
  }
  # SSE-KMS on both buckets: only through S3.
  statement {
    sid       = "ObjectsEncryption"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [var.kms_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${local.region}.amazonaws.com"]
    }
  }
  # Envelope encryption of stored secrets (managed secrets, signing keys, OIDC client
  # secrets): data keys generated and unwrapped directly, only with the record-bound
  # encryption context AgentGuard always sends.
  statement {
    sid       = "SealSecrets"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey"]
    resources = [var.kms_key_arn]
    condition {
      test     = "ForAnyValue:StringEquals"
      variable = "kms:EncryptionContextKeys"
      values   = ["agentguard:record"]
    }
  }
}

resource "aws_iam_role" "task" {
  for_each           = local.apps
  name               = "${var.name_prefix}-${each.key}-task"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy" "task" {
  for_each = local.with_objects
  name     = "objects"
  role     = aws_iam_role.task[each.key].id
  policy   = data.aws_iam_policy_document.objects.json
}

# Approval requests, invitations and incident notices: the api and the worker send
# through SES as the one allowed address (email module).
resource "aws_iam_role_policy" "mail" {
  for_each = var.send_mail ? toset(["api", "worker"]) : toset([])
  name     = "mail"
  role     = aws_iam_role.task[each.key].id
  policy   = var.mail_policy_json
}

# ─── Task definitions ────────────────────────────────────────────────────────

locals {
  log_options = {
    for k in keys(local.apps) : k => {
      logDriver = "awslogs"
      options = {
        awslogs-group         = var.log_group_names[k]
        awslogs-region        = local.region
        awslogs-stream-prefix = k
      }
    }
  }

  main_container = {
    for k, a in local.apps : k => {
      name                   = k
      image                  = a.image
      essential              = true
      readonlyRootFilesystem = true
      command                = a.command
      portMappings           = a.service ? [{ containerPort = a.port, protocol = "tcp" }] : []
      environment            = [for n, v in local.environment[a.env] : { name = n, value = v }]
      secrets                = local.secrets[a.env]
      linuxParameters        = { initProcessEnabled = true }
      # SIGTERM first: the api drains in-flight requests, the worker stops claiming and
      # finishes running jobs, the egress proxy stops accepting and lets tunnels finish.
      # ECS waits before SIGKILL.
      stopTimeout = a.stop_timeout
      mountPoints = [
        for p in a.writable_paths : { sourceVolume = trim(replace(p, "/", "-"), "-."), containerPath = p, readOnly = false }
      ]
      healthCheck = a.health == null ? null : {
        command     = a.health
        interval    = 15
        timeout     = 5
        retries     = 3
        startPeriod = a.start_period
      }
      logConfiguration = local.log_options[k]
    }
  }
}

resource "aws_ecs_task_definition" "this" {
  for_each                 = local.apps
  family                   = "${var.name_prefix}-${each.key}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = each.value.cpu
  memory                   = each.value.memory
  execution_role_arn       = aws_iam_role.execution[each.key].arn
  task_role_arn            = aws_iam_role.task[each.key].arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.cpu_architecture
  }

  dynamic "volume" {
    for_each = toset([for p in each.value.writable_paths : trim(replace(p, "/", "-"), "-.")])
    content {
      name = volume.value
    }
  }

  container_definitions = jsonencode([local.main_container[each.key]])
}

# ─── Services + autoscaling ──────────────────────────────────────────────────

resource "aws_ecs_service" "this" {
  for_each               = local.services
  name                   = each.key
  cluster                = aws_ecs_cluster.this.arn
  task_definition        = aws_ecs_task_definition.this[each.key].arn
  desired_count          = each.value.min_count
  launch_type            = "FARGATE"
  enable_execute_command = false
  propagate_tags         = "SERVICE"

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.task[each.key].id]
    assign_public_ip = false
  }

  dynamic "load_balancer" {
    for_each = each.value.public ? [1] : []
    content {
      target_group_arn = aws_lb_target_group.this[each.key].arn
      container_name   = each.key
      container_port   = each.value.port
    }
  }

  dynamic "service_registries" {
    for_each = each.value.discover ? [1] : []
    content {
      registry_arn = aws_service_discovery_service.this[each.key].arn
    }
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }
  # Rolling, never below the running count. Two worker generations may overlap: jobs are
  # claimed with leases and periodic tasks run under advisory locks, so that is safe.
  # Limits and the kill switch live in Redis and Postgres, so two api or egress
  # generations enforce the same numbers.
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200
  health_check_grace_period_seconds  = each.value.public ? each.value.start_period : null

  # Autoscaling owns the running count after the first deploy.
  lifecycle {
    ignore_changes = [desired_count]
  }
  depends_on = [aws_lb_listener.https, aws_lb_listener_rule.api]
}

resource "aws_appautoscaling_target" "this" {
  for_each           = local.scaled
  service_namespace  = "ecs"
  scalable_dimension = "ecs:service:DesiredCount"
  resource_id        = "service/${aws_ecs_cluster.this.name}/${aws_ecs_service.this[each.key].name}"
  min_capacity       = each.value.min_count
  max_capacity       = each.value.max_count
}

# CPU is the honest signal for all four: policy evaluation and scanning on the api, the
# worker's behavioural analysis, the proxy's TLS tunnels and the web's rendering.
resource "aws_appautoscaling_policy" "cpu" {
  for_each           = aws_appautoscaling_target.this
  name               = "${var.name_prefix}-${each.key}-cpu"
  policy_type        = "TargetTrackingScaling"
  service_namespace  = each.value.service_namespace
  scalable_dimension = each.value.scalable_dimension
  resource_id        = each.value.resource_id
  target_tracking_scaling_policy_configuration {
    target_value = var.cpu_target_percent
    # Scale in slowly: live feed sockets and proxy tunnels reconnect, but churn helps no one.
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
  }
}
