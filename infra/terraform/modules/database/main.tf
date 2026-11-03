# PostgreSQL 16 on RDS for every AgentGuard table: organisations, users and roles,
# agents and their credentials, tools, MCP servers, policies and their versions,
# decisions, approvals, secrets (envelope encrypted), threats, incidents, usage counters,
# jobs (the transactional outbox the workers claim with leases) and the hash-chained,
# append-only audit log (the database itself refuses updates and deletes on it).
# Evidence, exports and audit checkpoints live in S3; rows keep only their key. No
# extension beyond what RDS ships is needed.
resource "aws_db_subnet_group" "this" {
  name       = "${var.name_prefix}-db"
  subnet_ids = var.subnet_ids
}

# Ingress is added by the consumers (the api, worker and migrate tasks) against this
# group, so access is granted per security group, never by CIDR.
resource "aws_security_group" "db" {
  name        = "${var.name_prefix}-db"
  description = "PostgreSQL; ingress only from application security groups"
  vpc_id      = var.vpc_id
  tags        = { Name = "${var.name_prefix}-db" }
}

resource "aws_db_parameter_group" "this" {
  name   = "${var.name_prefix}-pg"
  family = "postgres${split(".", var.engine_version)[0]}"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
  parameter {
    name  = "log_min_duration_statement"
    value = "1000"
  }
  # A transaction left open by a crashed task must not hold row locks (a claimed job, a
  # rollup row) for long.
  parameter {
    name  = "idle_in_transaction_session_timeout"
    value = "60000"
  }
}

# The API reads one DATABASE_URL, so Terraform generates the master password and the
# secrets module stores the complete URL. Rotation: `terraform apply
# -replace=module.database.random_password.master`, then force a new ECS deployment.
# URL-safe characters only, so the password needs no escaping inside the URL.
resource "random_password" "master" {
  length           = 40
  special          = true
  override_special = "-_"
}

data "aws_iam_policy_document" "monitoring_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["monitoring.rds.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "monitoring" {
  count              = var.monitoring_interval > 0 ? 1 : 0
  name               = "${var.name_prefix}-rds-monitoring"
  assume_role_policy = data.aws_iam_policy_document.monitoring_assume.json
}

resource "aws_iam_role_policy_attachment" "monitoring" {
  count      = var.monitoring_interval > 0 ? 1 : 0
  role       = aws_iam_role.monitoring[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

resource "aws_db_instance" "this" {
  #checkov:skip=CKV_AWS_157:Multi-AZ is an input (aws-prod enables it; aws-dev trades it for cost).
  #checkov:skip=CKV_AWS_293:Deletion protection is an input (aws-prod enables it).
  identifier     = "${var.name_prefix}-db"
  engine         = "postgres"
  engine_version = var.engine_version
  instance_class = var.instance_class

  db_name  = var.database_name
  username = var.master_username
  password = random_password.master.result

  allocated_storage     = var.allocated_storage
  max_allocated_storage = var.max_allocated_storage
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = var.kms_key_arn

  db_subnet_group_name   = aws_db_subnet_group.this.name
  vpc_security_group_ids = [aws_security_group.db.id]
  parameter_group_name   = aws_db_parameter_group.this.name
  publicly_accessible    = false
  multi_az               = var.multi_az

  backup_retention_period    = var.backup_retention_days
  backup_window              = "03:00-04:00"
  maintenance_window         = "sun:04:30-sun:05:30"
  auto_minor_version_upgrade = true
  copy_tags_to_snapshot      = true
  deletion_protection        = var.deletion_protection
  skip_final_snapshot        = var.skip_final_snapshot
  final_snapshot_identifier  = var.skip_final_snapshot ? null : "${var.name_prefix}-db-final"

  iam_database_authentication_enabled = true
  monitoring_interval                 = var.monitoring_interval
  monitoring_role_arn                 = var.monitoring_interval > 0 ? aws_iam_role.monitoring[0].arn : null

  performance_insights_enabled          = true
  performance_insights_kms_key_id       = var.kms_key_arn
  performance_insights_retention_period = 7
  enabled_cloudwatch_logs_exports       = ["postgresql", "upgrade"]
}
