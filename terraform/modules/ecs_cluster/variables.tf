# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Declares the ECS cluster name, ECS Exec encryption, and audit-log retention.

variable "name" {
  type        = string
  description = "ECS cluster and ECS Exec log-group name."

  validation {
    condition     = can(regex("^[A-Za-z0-9_-]{3,255}$", var.name))
    error_message = "name must contain 3-255 ECS-compatible characters."
  }
}

variable "kms_key_arn" {
  type        = string
  description = "Customer-managed KMS key ARN used by ECS Exec and its CloudWatch log group."

  validation {
    condition     = can(regex("^arn:[^:]+:kms:[^:]+:[0-9]{12}:key/", var.kms_key_arn))
    error_message = "kms_key_arn must be a valid KMS key ARN."
  }
}

variable "log_retention_days" {
  type        = number
  description = "ECS Exec log retention; one year is the security baseline."
  default     = 365

  validation {
    condition     = floor(var.log_retention_days) == var.log_retention_days && var.log_retention_days >= 365
    error_message = "log_retention_days must be a whole number of at least 365."
  }
}

variable "tags" {
  type        = map(string)
  description = "Common ownership, environment, cost, and governance tags."
  default     = {}
}
