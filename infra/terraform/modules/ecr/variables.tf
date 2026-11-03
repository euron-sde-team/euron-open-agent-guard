variable "name_prefix" {
  description = "Repositories are named <name_prefix>/<image>."
  type        = string
}

variable "repositories" {
  description = "Images to create repositories for. server also runs the worker, the egress proxy, migrate, create-admin and seed-demo."
  type        = list(string)
  default     = ["server", "web", "sandbox"]
}

variable "kms_key_arn" {
  description = "CMK for repository encryption. Null uses AES256."
  type        = string
  default     = null
}

variable "keep_images" {
  description = "Tagged images kept per repository."
  type        = number
  default     = 30
}

variable "force_delete" {
  description = "Allow destroying a repository that still holds images."
  type        = bool
  default     = false
}
