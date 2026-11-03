variable "name_prefix" {
  description = "Prefix for every resource name. The buckets are <name_prefix>-objects and <name_prefix>-audit."
  type        = string
}

variable "kms_key_arn" {
  description = "CMK for SSE-KMS. Null falls back to SSE-S3."
  type        = string
  default     = null
}

variable "enforce_tls" {
  description = "Deny any request not made over TLS. Disable only for an emulator that speaks plain HTTP."
  type        = bool
  default     = true
}

variable "noncurrent_retention_days" {
  description = "Days a replaced or deleted object version stays recoverable."
  type        = number
  default     = 30
  validation {
    condition     = var.noncurrent_retention_days >= 1
    error_message = "noncurrent_retention_days must be at least 1."
  }
}

variable "export_expiration_days" {
  description = "Days an incident or compliance export (exports/) is kept."
  type        = number
  default     = 7
  validation {
    condition     = var.export_expiration_days >= 1
    error_message = "export_expiration_days must be at least 1."
  }
}

variable "backup_retention_days" {
  description = "Days a database backup (backups/) is kept."
  type        = number
  default     = 35
  validation {
    condition     = var.backup_retention_days >= 1
    error_message = "backup_retention_days must be at least 1."
  }
}

variable "cors_origins" {
  description = "Browser origins allowed to GET objects with JavaScript (the dashboard URL). Empty = no CORS configuration."
  type        = list(string)
  default     = []
}

variable "force_destroy" {
  description = "Allow `terraform destroy` to delete a non-empty objects bucket. Never in production."
  type        = bool
  default     = false
}

variable "audit_lock_mode" {
  description = "S3 Object Lock mode for audit checkpoints: COMPLIANCE (nobody can shorten or remove the lock, not even the account root) or GOVERNANCE (principals with s3:BypassGovernanceRetention can)."
  type        = string
  default     = "COMPLIANCE"
  validation {
    condition     = contains(["COMPLIANCE", "GOVERNANCE"], var.audit_lock_mode)
    error_message = "audit_lock_mode must be COMPLIANCE or GOVERNANCE."
  }
}

variable "audit_retention_days" {
  description = "Days every audit checkpoint version stays locked (and then one more day before it expires)."
  type        = number
  default     = 365
  validation {
    condition     = var.audit_retention_days >= 1
    error_message = "audit_retention_days must be at least 1."
  }
}

variable "audit_force_destroy" {
  description = "Allow `terraform destroy` to delete a non-empty audit bucket (still impossible while a version is under a COMPLIANCE lock). Throwaway environments only."
  type        = bool
  default     = false
}
