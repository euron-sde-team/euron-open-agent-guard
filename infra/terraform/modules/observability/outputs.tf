output "log_group_names" {
  description = "Log group per app: { api, worker, egress, web, migrate, sandbox } (service and sandbox module log groups)."
  value       = { for k, g in aws_cloudwatch_log_group.app : k => g.name }
}

output "alarm_topic_arn" {
  description = "SNS topic receiving every alarm."
  value       = aws_sns_topic.alarms.arn
}

output "dashboard_name" {
  description = "CloudWatch dashboard."
  value       = aws_cloudwatch_dashboard.this.dashboard_name
}

output "metrics_namespace" {
  description = "Namespace of the security and job metrics extracted from the logs."
  value       = local.namespace
}
