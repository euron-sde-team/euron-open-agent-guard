# The sandbox: ECS tasks on EC2 capacity of their own, in a cluster of their own, the only
# place AgentGuard runs untrusted Python, Node.js and shell.
#
#   api / worker ──► sandbox task (POST /run with SANDBOX_TOKEN) ──► nsjail, one per run
#                                                                      │ only when policy
#                                                                      ▼ grants it
#                                                         egress proxy (network policy)
#
# Why EC2 and not Fargate: nsjail builds each run's sandbox from user namespaces, which
# needs Docker's default seccomp profile plus the namespace syscalls, and Fargate cannot
# take a custom seccomp profile. These instances run only sandbox tasks, so the profile
# (infra/docker/sandbox-seccomp.json) is the Docker daemon's default here, written by the
# user data, and nothing else on the cluster gets it.
#
# Defense in depth around code that is hostile by assumption:
#
#   - the task: every Linux capability dropped, no-new-privileges, privileged off,
#     read-only root, a size-bounded tmpfs for scratch, memory and process limits, the
#     image's non-root user (10001)
#   - inside it, nsjail gives each run fresh user, PID, network, mount, IPC and UTS
#     namespaces, rlimits, a read-only view of the runtimes and a private scratch tmpfs,
#     and no network interface at all; in proxy mode the only way out is a socket the
#     service relays to the egress proxy, which applies the agent's network policy
#   - the network: the task accepts connections only from the api and the worker on its
#     port, and may connect only to the egress proxy (no internet, no database, no cache,
#     no metadata service); the instance itself reaches only HTTPS for ECS, ECR,
#     CloudWatch Logs, Secrets Manager and Session Manager
#   - instance metadata: IMDSv2 only with a hop limit of 1, and the ECS agent blocks task
#     access to it (ECS_AWSVPC_BLOCK_IMDS), so a sandbox escape cannot borrow the
#     instance role
#   - IAM: the task role has no policy at all; the execution role injects only
#     SANDBOX_TOKEN. A compromised sandbox holds no database, storage, signing or
#     session secret.
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

data "aws_ssm_parameter" "ami" {
  count = var.ami_id == null ? 1 : 0
  name  = "/aws/service/ecs/optimized-ami/amazon-linux-2023/arm64/recommended/image_id"
}

locals {
  region  = data.aws_region.current.region
  ami_id  = coalesce(var.ami_id, try(data.aws_ssm_parameter.ami[0].value, null))
  cluster = "${var.name_prefix}-sandbox"
  url     = "http://sandbox.${var.namespace_name}:${var.port}"
}

resource "aws_ecs_cluster" "this" {
  name = local.cluster
  setting {
    name  = "containerInsights"
    value = var.container_insights
  }
}

# ─── Security groups ─────────────────────────────────────────────────────────

# The sandbox tasks (awsvpc: each task has its own network interface and this group).
resource "aws_security_group" "task" {
  name        = "${var.name_prefix}-sandbox-task"
  description = "Sandbox tasks: ingress only from the api and worker, egress only to the egress proxy"
  vpc_id      = var.vpc_id
  tags        = { Name = "${var.name_prefix}-sandbox-task" }
}

resource "aws_vpc_security_group_ingress_rule" "from_callers" {
  for_each                     = var.caller_security_group_ids
  security_group_id            = aws_security_group.task.id
  description                  = "From ${each.key} tasks"
  referenced_security_group_id = each.value
  ip_protocol                  = "tcp"
  from_port                    = var.port
  to_port                      = var.port
}

resource "aws_vpc_security_group_egress_rule" "callers_to_sandbox" {
  for_each                     = var.caller_security_group_ids
  security_group_id            = each.value
  description                  = "To sandbox tasks"
  referenced_security_group_id = aws_security_group.task.id
  ip_protocol                  = "tcp"
  from_port                    = var.port
  to_port                      = var.port
}

resource "aws_vpc_security_group_egress_rule" "to_egress" {
  security_group_id            = aws_security_group.task.id
  description                  = "To the egress proxy (the only way out, under network policy)"
  referenced_security_group_id = var.egress_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = var.egress_port
  to_port                      = var.egress_port
}

resource "aws_vpc_security_group_ingress_rule" "egress_from_sandbox" {
  security_group_id            = var.egress_security_group_id
  description                  = "From sandbox tasks"
  referenced_security_group_id = aws_security_group.task.id
  ip_protocol                  = "tcp"
  from_port                    = var.egress_port
  to_port                      = var.egress_port
}

# Cloud Map names (egress.<name_prefix>.internal) resolve through the VPC resolver.
resource "aws_vpc_security_group_egress_rule" "dns" {
  for_each          = toset(["udp", "tcp"])
  security_group_id = aws_security_group.task.id
  description       = "DNS to the VPC resolver (${each.key})"
  cidr_ipv4         = var.vpc_cidr_block
  ip_protocol       = each.key
  from_port         = 53
  to_port           = 53
}

# The instances: the ECS agent, image pulls, logs, secrets and Session Manager, over
# HTTPS only.
resource "aws_security_group" "instance" {
  name        = "${var.name_prefix}-sandbox-instance"
  description = "Sandbox EC2 hosts: HTTPS egress for ECS, ECR, logs, secrets and Session Manager; no ingress"
  vpc_id      = var.vpc_id
  tags        = { Name = "${var.name_prefix}-sandbox-instance" }
}

resource "aws_vpc_security_group_egress_rule" "instance_https" {
  security_group_id = aws_security_group.instance.id
  description       = "HTTPS to ECS, ECR, CloudWatch Logs, Secrets Manager and Session Manager"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

# ─── Service discovery ───────────────────────────────────────────────────────

resource "aws_service_discovery_service" "this" {
  name = "sandbox"
  dns_config {
    namespace_id   = var.namespace_id
    routing_policy = "MULTIVALUE"
    dns_records {
      type = "A"
      ttl  = 10
    }
  }
  # ECS reports task health; unhealthy tasks leave DNS without a Route53 health check.
  health_check_custom_config {}
}

# ─── IAM ─────────────────────────────────────────────────────────────────────

data "aws_iam_policy_document" "assume_ec2" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "instance" {
  name               = "${var.name_prefix}-sandbox-instance"
  assume_role_policy = data.aws_iam_policy_document.assume_ec2.json
}

resource "aws_iam_role_policy_attachment" "instance" {
  for_each = toset([
    "service-role/AmazonEC2ContainerServiceforEC2Role",
    "AmazonSSMManagedInstanceCore",
  ])
  role       = aws_iam_role.instance.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/${each.key}"
}

resource "aws_iam_instance_profile" "this" {
  name = "${var.name_prefix}-sandbox"
  role = aws_iam_role.instance.name
}

data "aws_iam_policy_document" "assume_task" {
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

# Execution role: pull the image, write logs, inject SANDBOX_TOKEN. Nothing else.
resource "aws_iam_role" "execution" {
  name               = "${var.name_prefix}-sandbox-execution"
  assume_role_policy = data.aws_iam_policy_document.assume_task.json
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

data "aws_iam_policy_document" "execution" {
  statement {
    sid       = "InjectSandboxToken"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = distinct([for s in var.secrets : regex("^(arn:[^:]+:secretsmanager:[^:]+:[^:]+:secret:[^:]+)", s.valueFrom)[0]])
  }
  statement {
    sid       = "DecryptSandboxToken"
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
  name   = "sandbox-secrets"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.execution.json
}

# Task role: no policy. The sandbox calls no AWS API.
resource "aws_iam_role" "task" {
  name               = "${var.name_prefix}-sandbox-task"
  assume_role_policy = data.aws_iam_policy_document.assume_task.json
}

# ─── Capacity: launch template, Auto Scaling group, capacity provider ────────

resource "aws_launch_template" "this" {
  name_prefix            = "${var.name_prefix}-sandbox-"
  image_id               = local.ami_id
  instance_type          = var.instance_type
  vpc_security_group_ids = [aws_security_group.instance.id]
  ebs_optimized          = true

  iam_instance_profile {
    arn = aws_iam_instance_profile.this.arn
  }

  metadata_options {
    http_tokens                 = "required"
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1
  }

  monitoring {
    enabled = true
  }

  # Encrypted with the account's EBS key: the root volume holds only images and logs (run
  # scratch space is tmpfs), and a customer key here would need a grant for the Auto
  # Scaling service-linked role, which may not exist yet in a fresh account.
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      encrypted             = true
      volume_type           = "gp3"
      volume_size           = var.root_volume_gib
      delete_on_termination = true
    }
  }

  # Gzipped (cloud-init unpacks it): user data is capped at 16 KB.
  user_data = base64gzip(templatefile("${path.module}/user_data.sh.tftpl", {
    cluster         = local.cluster
    seccomp_profile = jsonencode(jsondecode(var.seccomp_profile_json))
  }))

  tag_specifications {
    resource_type = "instance"
    tags          = { Name = "${var.name_prefix}-sandbox" }
  }
}

resource "aws_autoscaling_group" "this" {
  name_prefix           = "${var.name_prefix}-sandbox-"
  vpc_zone_identifier   = var.private_subnet_ids
  min_size              = var.min_instances
  max_size              = var.max_instances
  desired_capacity      = var.min_instances
  protect_from_scale_in = true
  health_check_type     = "EC2"

  launch_template {
    id      = aws_launch_template.this.id
    version = aws_launch_template.this.latest_version
  }

  # A new launch template (a new AMI, a new profile) rolls the fleet gradually.
  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 50
    }
  }

  tag {
    key                 = "AmazonECSManaged"
    value               = "true"
    propagate_at_launch = true
  }

  # The capacity provider owns the instance count after creation.
  lifecycle {
    ignore_changes = [desired_capacity]
  }
}

resource "aws_ecs_capacity_provider" "this" {
  name = "${var.name_prefix}-sandbox"
  auto_scaling_group_provider {
    auto_scaling_group_arn         = aws_autoscaling_group.this.arn
    managed_termination_protection = "ENABLED"
    managed_draining               = "ENABLED"
    managed_scaling {
      status                    = "ENABLED"
      target_capacity           = 100
      minimum_scaling_step_size = 1
      maximum_scaling_step_size = 2
    }
  }
}

resource "aws_ecs_cluster_capacity_providers" "this" {
  cluster_name       = aws_ecs_cluster.this.name
  capacity_providers = [aws_ecs_capacity_provider.this.name]
  default_capacity_provider_strategy {
    capacity_provider = aws_ecs_capacity_provider.this.name
    weight            = 1
  }
}

# ─── Task definition and service ─────────────────────────────────────────────

resource "aws_ecs_task_definition" "this" {
  family                   = "${var.name_prefix}-sandbox"
  requires_compatibilities = ["EC2"]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }

  container_definitions = jsonencode([{
    name                   = "sandbox"
    image                  = var.image
    essential              = true
    user                   = "10001:10001"
    readonlyRootFilesystem = true
    privileged             = false
    dockerSecurityOptions  = ["no-new-privileges"]
    portMappings           = [{ containerPort = var.port, protocol = "tcp" }]
    environment = [for n, v in merge({
      SANDBOX_HOST      = "0.0.0.0"
      SANDBOX_PORT      = tostring(var.port)
      SANDBOX_LOG_LEVEL = "INFO"
      # Runs at once x the largest memory a run may ask for, plus the scratch tmpfs and
      # the service, must stay inside task_memory.
      SANDBOX_CONCURRENCY   = tostring(var.concurrency)
      SANDBOX_MAX_MEMORY_MB = tostring(var.max_run_memory_mib)
    }, var.environment) : { name = n, value = v }]
    secrets = var.secrets
    linuxParameters = {
      initProcessEnabled = true
      capabilities       = { drop = ["ALL"] }
      tmpfs = [
        # Per-run working directories (code, input files, the egress socket); private to
        # this task. Each nsjail mounts its own size-limited tmpfs inside the run.
        { containerPath = "/tmp", size = var.tmp_mib, mountOptions = ["exec", "nosuid", "nodev", "mode=1777"] },
      ]
    }
    ulimits = [
      { name = "nproc", softLimit = var.max_processes, hardLimit = var.max_processes },
      { name = "nofile", softLimit = 4096, hardLimit = 4096 },
      { name = "core", softLimit = 0, hardLimit = 0 },
    ]
    healthCheck = {
      command     = ["CMD", "python", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:${var.port}/healthz', timeout=3).status == 200 else 1)"]
      interval    = 15
      timeout     = 5
      retries     = 3
      startPeriod = 20
    }
    # SIGTERM: the service stops accepting and lets running programs finish within their
    # wall clock limit.
    stopTimeout = 60
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = var.log_group_name
        awslogs-region        = local.region
        awslogs-stream-prefix = "sandbox"
      }
    }
  }])
}

resource "aws_ecs_service" "this" {
  name                   = "sandbox"
  cluster                = aws_ecs_cluster.this.arn
  task_definition        = aws_ecs_task_definition.this.arn
  desired_count          = var.min_tasks
  enable_execute_command = false
  propagate_tags         = "SERVICE"

  capacity_provider_strategy {
    capacity_provider = aws_ecs_capacity_provider.this.name
    weight            = 1
  }

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.task.id]
    assign_public_ip = false
  }

  service_registries {
    registry_arn = aws_service_discovery_service.this.arn
  }

  ordered_placement_strategy {
    type  = "spread"
    field = "attribute:ecs.availability-zone"
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }
  # A run is short and synchronous: the api retries a run whose task went away, so a
  # rolling deploy may stop half the tasks at a time.
  deployment_minimum_healthy_percent = 50
  deployment_maximum_percent         = 200

  lifecycle {
    ignore_changes = [desired_count]
  }
  depends_on = [aws_ecs_cluster_capacity_providers.this]
}

resource "aws_appautoscaling_target" "this" {
  service_namespace  = "ecs"
  scalable_dimension = "ecs:service:DesiredCount"
  resource_id        = "service/${aws_ecs_cluster.this.name}/${aws_ecs_service.this.name}"
  min_capacity       = var.min_tasks
  max_capacity       = var.max_tasks
}

# Running code is CPU bound, so CPU says when more sandboxes are needed; the capacity
# provider then adds instances to fit the tasks.
resource "aws_appautoscaling_policy" "cpu" {
  name               = "${var.name_prefix}-sandbox-cpu"
  policy_type        = "TargetTrackingScaling"
  service_namespace  = aws_appautoscaling_target.this.service_namespace
  scalable_dimension = aws_appautoscaling_target.this.scalable_dimension
  resource_id        = aws_appautoscaling_target.this.resource_id
  target_tracking_scaling_policy_configuration {
    target_value       = var.cpu_target_percent
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
  }
}
