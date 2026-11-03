output "identity_arn" {
  description = "SES domain identity ARN."
  value       = aws_sesv2_email_identity.this.arn
}

output "configuration_set_name" {
  description = "SES configuration set every message goes through (bounce and complaint metrics)."
  value       = aws_sesv2_configuration_set.this.configuration_set_name
}

output "send_policy_json" {
  description = "IAM policy for the api and worker task roles: send only as from_address, only through this identity."
  value       = data.aws_iam_policy_document.send.json
}

output "dkim_records" {
  description = "DKIM CNAMEs to publish when no Route53 zone is given: name => value."
  value = {
    for t in aws_sesv2_email_identity.this.dkim_signing_attributes[0].tokens :
    "${t}._domainkey.${var.domain}" => "${t}.dkim.amazonses.com"
  }
}
