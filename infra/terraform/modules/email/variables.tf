variable "name_prefix" {
  description = "Prefix for every resource name."
  type        = string
}

variable "domain" {
  description = "Domain mail is sent from (an SES domain identity), e.g. agentguard.example.com."
  type        = string
}

variable "from_address" {
  description = "The only From address the api and worker may send as (MAIL_FROM_ADDRESS), e.g. agentguard@agentguard.example.com."
  type        = string
  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+$", var.from_address))
    error_message = "from_address must be an email address."
  }
}

variable "route53_zone_id" {
  description = "Hosted zone that receives the DKIM records. Null: create them yourself (dkim_records output)."
  type        = string
  default     = null
}
