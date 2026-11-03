variable "endpoint" {
  description = "Emulator endpoint. http://floci:4566 inside compose, http://localhost:5166 from the host."
  type        = string
  default     = "http://localhost:5166"
}

variable "name_prefix" {
  description = "Must match OBJECTS_BUCKET (<name_prefix>-objects), AUDIT_BUCKET (<name_prefix>-audit) and KMS_KEY_ID (alias/<name_prefix>) in deploy/compose/compose.floci.yaml."
  type        = string
  default     = "agentguard-local"
}

variable "cors_origins" {
  description = "Dashboard origins allowed to fetch objects with JavaScript."
  type        = list(string)
  default     = ["http://localhost:5110", "http://127.0.0.1:5110"]
}

variable "mail_domain" {
  description = "SES domain identity created on the emulator (the domain of MAIL_FROM_ADDRESS locally)."
  type        = string
  default     = "agentguard.local"
}

variable "mail_from_address" {
  description = "From address the send policy allows (MAIL_FROM_ADDRESS locally)."
  type        = string
  default     = "agentguard@agentguard.local"
}
