output "objects_bucket" {
  description = "OBJECTS_BUCKET for the local stack."
  value       = module.storage.bucket_name
}

output "audit_bucket" {
  description = "AUDIT_BUCKET (Object Lock) for the local stack."
  value       = module.storage.audit_bucket_name
}

output "kms_key_alias" {
  description = "KMS_KEY_ID for the local stack."
  value       = module.kms.alias_name
}

output "app_secret_arn" {
  description = "The emulated Secrets Manager secret (SESSION_SECRET, TOKEN_PEPPER, SANDBOX_TOKEN)."
  value       = module.secrets.secret_arn
}

output "mail_identity_arn" {
  description = "The emulated SES domain identity."
  value       = module.email.identity_arn
}
