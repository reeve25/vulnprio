variable "region" {
  type    = string
  default = "us-east-1"
}

variable "name" {
  type    = string
  default = "vulnprio"
}

variable "image_tag" {
  description = "Immutable image tag in ECR (CI pushes the git SHA)."
  type        = string
}

variable "github_repo" {
  description = "owner/repo allowed to assume the CI role (main branch only)."
  type        = string
  default     = "reeve25/vulnprio"
}

variable "alarm_email" {
  description = "Email for alarm notifications; null = no subscription."
  type        = string
  default     = null
}

variable "log_retention_days" {
  type    = number
  default = 30
}
