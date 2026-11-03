output "url" {
  description = "SANDBOX_URL for the api and worker (Cloud Map name in the service module's namespace)."
  value       = local.url
}

output "cluster_name" {
  description = "Sandbox ECS cluster name."
  value       = aws_ecs_cluster.this.name
}

output "service_name" {
  description = "Sandbox ECS service name."
  value       = aws_ecs_service.this.name
}

output "security_group_id" {
  description = "Sandbox task security group."
  value       = aws_security_group.task.id
}

output "autoscaling_group_name" {
  description = "Sandbox hosts' Auto Scaling group."
  value       = aws_autoscaling_group.this.name
}
