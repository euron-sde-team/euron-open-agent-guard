# Two private buckets for everything too large or too permanent to keep in Postgres.
#
# <name_prefix>-objects (OBJECTS_BUCKET), versioned:
#   orgs/<org id>/evidence/  incident evidence (decision snapshots, tool outputs, egress
#                            records). Rows keep only the key; downloads go through the
#                            api, which checks the caller's organisation first.
#   exports/                 incident and compliance exports (Markdown, JSON); short lived.
#   backups/                 database dumps; kept backup_retention_days.
#   An overwritten or deleted object stays recoverable for noncurrent_retention_days.
#
# <name_prefix>-audit (AUDIT_BUCKET), versioned with S3 Object Lock:
#   checkpoints/             signed audit checkpoints (the head hash of the audit chain at
#                            a point in time, Ed25519 signed). Every object version is
#                            locked for audit_retention_days in audit_lock_mode from the
#                            moment it is written: nobody, including AgentGuard itself, can
#                            change or delete a checkpoint inside that window (COMPLIANCE
#                            mode binds the account root as well). `agentguard verify`
#                            compares the database chain against these checkpoints, so a
#                            rewritten history cannot also rewrite its anchors.
resource "aws_s3_bucket" "objects" {
  #checkov:skip=CKV_AWS_144:Cross-region replication doubles where customer data lives (a data-residency decision for the operator); versioning and backups cover recovery (docs/guides/operations.md).
  #checkov:skip=CKV_AWS_18:Access logging targets a separate log bucket an operator chooses; CloudTrail data events cover object access (docs/guides/operations.md).
  #checkov:skip=CKV2_AWS_62:No consumer for S3 event notifications; the worker writes and reads these objects itself.
  bucket        = "${var.name_prefix}-objects"
  force_destroy = var.force_destroy
}

resource "aws_s3_bucket_versioning" "objects" {
  bucket = aws_s3_bucket.objects.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "objects" {
  bucket                  = aws_s3_bucket.objects.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "objects" {
  bucket = aws_s3_bucket.objects.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "objects" {
  bucket = aws_s3_bucket.objects.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.kms_key_arn != null ? "aws:kms" : "AES256"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = var.kms_key_arn != null
  }
}

resource "aws_s3_bucket" "audit" {
  #checkov:skip=CKV_AWS_144:Cross-region replication doubles where customer data lives (a data-residency decision for the operator); versioning and Object Lock cover recovery (docs/guides/operations.md).
  #checkov:skip=CKV_AWS_18:Access logging targets a separate log bucket an operator chooses; CloudTrail data events cover object access (docs/guides/operations.md).
  #checkov:skip=CKV2_AWS_62:No consumer for S3 event notifications; the worker writes and reads these objects itself.
  bucket        = "${var.name_prefix}-audit"
  force_destroy = var.audit_force_destroy
  # Object Lock can only be switched on for a bucket at creation.
  object_lock_enabled = true
}

resource "aws_s3_bucket_versioning" "audit" {
  bucket = aws_s3_bucket.audit.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "audit" {
  bucket                  = aws_s3_bucket.audit.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.kms_key_arn != null ? "aws:kms" : "AES256"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = var.kms_key_arn != null
  }
}

# Every checkpoint version is locked on write (see the header).
resource "aws_s3_bucket_object_lock_configuration" "audit" {
  bucket     = aws_s3_bucket.audit.id
  depends_on = [aws_s3_bucket_versioning.audit]
  rule {
    default_retention {
      mode = var.audit_lock_mode
      days = var.audit_retention_days
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "objects" {
  bucket     = aws_s3_bucket.objects.id
  depends_on = [aws_s3_bucket_versioning.objects]

  rule {
    id     = "abort-incomplete-multipart"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }

  # Replaced or deleted versions stay recoverable for a while, then go.
  rule {
    id     = "expire-noncurrent"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration {
      noncurrent_days = var.noncurrent_retention_days
    }
  }

  rule {
    id     = "expire-exports"
    status = "Enabled"
    filter {
      prefix = "exports/"
    }
    expiration {
      days = var.export_expiration_days
    }
  }

  rule {
    id     = "expire-backups"
    status = "Enabled"
    filter {
      prefix = "backups/"
    }
    expiration {
      days = var.backup_retention_days
    }
  }
}

# Checkpoints outlive their lock by a margin, then expire; a version still under lock
# cannot be removed by this rule either (S3 skips locked versions).
resource "aws_s3_bucket_lifecycle_configuration" "audit" {
  bucket     = aws_s3_bucket.audit.id
  depends_on = [aws_s3_bucket_versioning.audit]

  rule {
    id     = "abort-incomplete-multipart"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }

  rule {
    id     = "expire-noncurrent"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration {
      noncurrent_days = var.audit_retention_days + 1
    }
  }
}

# Only needed when a browser fetches exports with JavaScript; a presigned download link
# opened as a navigation needs none, so the default is no CORS at all.
resource "aws_s3_bucket_cors_configuration" "objects" {
  count  = length(var.cors_origins) > 0 ? 1 : 0
  bucket = aws_s3_bucket.objects.id
  cors_rule {
    allowed_methods = ["GET", "HEAD"]
    allowed_origins = var.cors_origins
    allowed_headers = ["*"]
    expose_headers  = ["Content-Disposition", "Content-Length", "ETag"]
    max_age_seconds = 3600
  }
}

locals {
  buckets = {
    objects = aws_s3_bucket.objects.arn
    audit   = aws_s3_bucket.audit.arn
  }
}

data "aws_iam_policy_document" "tls" {
  for_each = local.buckets
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [each.value, "${each.value}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "objects" {
  count      = var.enforce_tls ? 1 : 0
  bucket     = aws_s3_bucket.objects.id
  policy     = data.aws_iam_policy_document.tls["objects"].json
  depends_on = [aws_s3_bucket_public_access_block.objects]
}

resource "aws_s3_bucket_policy" "audit" {
  count      = var.enforce_tls ? 1 : 0
  bucket     = aws_s3_bucket.audit.id
  policy     = data.aws_iam_policy_document.tls["audit"].json
  depends_on = [aws_s3_bucket_public_access_block.audit]
}
