output "cluster_name" {
  description = "ECS cluster name."
  value       = aws_ecs_cluster.this.name
}

output "cluster_arn" {
  description = "ECS cluster ARN."
  value       = aws_ecs_cluster.this.arn
}

output "url" {
  description = "Public URL of the app and API."
  value       = local.public_url
}

output "internal_urls" {
  description = "Private service URLs through Cloud Map: { api, egress } (the web task's rewrite target and EGRESS_URL)."
  value       = local.internal_url
}

output "alb_dns_name" {
  description = "Load balancer DNS name (CNAME target for the host name when the zone is not in Route53)."
  value       = aws_lb.this.dns_name
}

output "alb_arn_suffix" {
  description = "Load balancer ARN suffix, for CloudWatch metrics."
  value       = aws_lb.this.arn_suffix
}

output "services" {
  description = "Load-balanced services: { api, web } => { service_name, target_group_arn_suffix }."
  value = {
    for k in keys(local.load_balanced) : k => {
      service_name            = aws_ecs_service.this[k].name
      target_group_arn_suffix = aws_lb_target_group.this[k].arn_suffix
    }
  }
}

output "service_names" {
  description = "Every ECS service name (api, worker, egress, web)."
  value       = { for k, s in aws_ecs_service.this : k => s.name }
}

output "security_group_ids" {
  description = "Task security group per app."
  value       = { for k, sg in aws_security_group.task : k => sg.id }
}

output "task_role_arns" {
  description = "Task role per app."
  value       = { for k, r in aws_iam_role.task : k => r.arn }
}

output "run_task" {
  description = "Parameters for one-off tasks: `agentguard migrate` (task_definition, the default), or `create-admin` and `seed-demo` as command overrides on the same definition."
  value = {
    cluster         = aws_ecs_cluster.this.name
    task_definition = aws_ecs_task_definition.this["migrate"].family
    container       = "migrate"
    subnets         = var.private_subnet_ids
    security_groups = [aws_security_group.task["migrate"].id]
  }
}

output "namespace_id" {
  description = "Cloud Map private DNS namespace (api, egress and the sandbox register in it)."
  value       = aws_service_discovery_private_dns_namespace.this.id
}

output "namespace_name" {
  description = "Cloud Map namespace name (<name_prefix>.internal)."
  value       = aws_service_discovery_private_dns_namespace.this.name
}

output "egress_port" {
  description = "Port of the egress proxy."
  value       = local.egress_port
}
