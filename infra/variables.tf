variable "region" {
  type    = string
  default = "us-west-2"
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

variable "reserved_concurrency" {
  description = "Lambda reserved concurrency (cost/abuse ceiling). -1 = none: new accounts have a 10-execution quota and AWS keeps 10 unreserved, so any reservation fails there (DECISIONS #17)."
  type        = number
  default     = 10
}

variable "allow_destroy" {
  description = "Demo teardown: drop DynamoDB deletion protection and let destroy empty the bucket and ECR repo. Apply with true, then destroy."
  type        = bool
  default     = false
}

variable "log_retention_days" {
  type    = number
  default = 30
}
