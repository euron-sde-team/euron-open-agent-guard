output "bucket_name" {
  description = "Objects bucket name (OBJECTS_BUCKET)."
  value       = aws_s3_bucket.objects.bucket
}

output "bucket_arn" {
  description = "Objects bucket ARN, for IAM policies."
  value       = aws_s3_bucket.objects.arn
}

output "audit_bucket_name" {
  description = "Object Lock bucket for signed audit checkpoints (AUDIT_BUCKET)."
  value       = aws_s3_bucket.audit.bucket
}

output "audit_bucket_arn" {
  description = "Audit checkpoint bucket ARN, for IAM policies."
  value       = aws_s3_bucket.audit.arn
}
