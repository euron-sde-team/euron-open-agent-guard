variable "name_prefix" {
  description = "Prefix for every resource name."
  type        = string
}

variable "vpc_id" {
  description = "VPC the sandboxes run in."
  type        = string
}

variable "vpc_cidr_block" {
  description = "VPC CIDR (DNS to the VPC resolver for Cloud Map names)."
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnets for the instances and task interfaces (no public IP)."
  type        = list(string)
}

variable "namespace_id" {
  description = "Cloud Map private DNS namespace to register sandbox.<namespace> in (service module namespace_id)."
  type        = string
}

variable "namespace_name" {
  description = "Name of that namespace (service module namespace_name), for the url output."
  type        = string
}

variable "image" {
  description = "Full sandbox image reference, e.g. <registry>/agentguard-prod/sandbox:<tag>."
  type        = string
}

variable "port" {
  description = "Port the sandbox service listens on (SANDBOX_PORT)."
  type        = number
  default     = 8080
}

variable "caller_security_group_ids" {
  description = "Security groups allowed to call the sandbox, by name: { api = <sg>, worker = <sg> } (service module security_group_ids)."
  type        = map(string)
}

variable "egress_security_group_id" {
  description = "The egress proxy's security group (service module security_group_ids.egress): the only destination the sandbox may reach."
  type        = string
}

variable "egress_port" {
  description = "Port of the egress proxy."
  type        = number
  default     = 3128
}

variable "secrets" {
  description = "ECS secrets for the sandbox (secrets module sandbox_secrets: SANDBOX_TOKEN only)."
  type = list(object({
    name      = string
    valueFrom = string
  }))
}

variable "environment" {
  description = "Extra sandbox environment (SANDBOX_* settings, see docs/guides/configuration.md). Never secrets."
  type        = map(string)
  default     = {}
}

variable "kms_key_arn" {
  description = "CMK that encrypts the injected secret (the execution role may decrypt through Secrets Manager only)."
  type        = string
}

variable "log_group_name" {
  description = "CloudWatch log group for the sandbox (observability module log_group_names.sandbox)."
  type        = string
}

variable "seccomp_profile_json" {
  description = "The sandbox seccomp profile (infra/docker/sandbox-seccomp.json): the Docker daemon default on the sandbox hosts."
  type        = string
  validation {
    condition     = can(jsondecode(var.seccomp_profile_json).syscalls)
    error_message = "seccomp_profile_json must be a Docker seccomp profile (JSON with a syscalls list)."
  }
}

variable "ami_id" {
  description = "Sandbox host AMI. Null: the latest ECS-optimized Amazon Linux 2023 ARM64 AMI."
  type        = string
  default     = null
}

variable "instance_type" {
  description = "ARM64 instance type for sandbox hosts. Compute optimized (c7g) suits running code."
  type        = string
  default     = "c7g.large"
}

variable "root_volume_gib" {
  description = "Root volume size of a sandbox host (images and logs; run scratch space is tmpfs)."
  type        = number
  default     = 30
}

variable "min_instances" {
  description = "Sandbox hosts kept running."
  type        = number
  default     = 1
}

variable "max_instances" {
  description = "Most sandbox hosts the capacity provider may run."
  type        = number
  default     = 4
}

variable "min_tasks" {
  description = "Sandbox tasks kept running."
  type        = number
  default     = 2
}

variable "max_tasks" {
  description = "Most sandbox tasks autoscaling may run."
  type        = number
  default     = 8
}

variable "task_cpu" {
  description = "CPU units per sandbox task (1024 = one vCPU)."
  type        = number
  default     = 1024
}

variable "task_memory" {
  description = "Memory per sandbox task in MiB: concurrency x max_run_memory_mib, plus tmp_mib (tmpfs pages count) and the service."
  type        = number
  default     = 4096
}

variable "concurrency" {
  description = "Programs one sandbox task runs at once (SANDBOX_CONCURRENCY)."
  type        = number
  default     = 2
}

variable "max_run_memory_mib" {
  description = "Largest memory limit one run may ask for (SANDBOX_MAX_MEMORY_MB)."
  type        = number
  default     = 1024
}

variable "tmp_mib" {
  description = "tmpfs size for /tmp (per-run working directories) in MiB."
  type        = number
  default     = 1024
}

variable "max_processes" {
  description = "nproc ulimit for the sandbox user, across every run in the task."
  type        = number
  default     = 512
}

variable "cpu_target_percent" {
  description = "Average sandbox CPU the autoscaler aims for."
  type        = number
  default     = 60
}

variable "container_insights" {
  description = "ECS Container Insights on the sandbox cluster (enabled, enhanced or disabled)."
  type        = string
  default     = "enabled"
}
