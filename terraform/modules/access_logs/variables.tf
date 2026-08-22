# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Declares centralized ALB and S3 access-log storage controls.

variable "name" {
  type        = string
  description = "Globally unique S3 bucket name used as the terminal access-log destination."

  validation {
    condition     = length(var.name) >= 3 && length(var.name) <= 63 && can(regex("^[a-z0-9][a-z0-9.-]*[a-z0-9]$", var.name))
    error_message = "name must be a valid 3-63 character lowercase S3 bucket name."
  }
}

variable "force_destroy" {
  type        = bool
  description = "Allow deletion of non-empty development log buckets. Keep false for production."
  default     = false
}

variable "alb_prefix" {
  type        = string
  description = "S3 object prefix used by ALB access-log delivery and its bucket-policy resource scope."
  default     = "alb"

  validation {
    condition     = trim(var.alb_prefix, "/") != "" && !startswith(var.alb_prefix, "/")
    error_message = "alb_prefix must be a non-empty relative S3 prefix."
  }
}

variable "retention_days" {
  type        = number
  description = "Retention period for current access-log objects."
  default     = 365

  validation {
    condition     = floor(var.retention_days) == var.retention_days && var.retention_days >= 365
    error_message = "retention_days must be a whole number of at least 365."
  }
}

variable "noncurrent_version_expiration_days" {
  type        = number
  description = "Retention period for superseded log-object versions."
  default     = 90

  validation {
    condition     = floor(var.noncurrent_version_expiration_days) == var.noncurrent_version_expiration_days && var.noncurrent_version_expiration_days >= 30
    error_message = "noncurrent_version_expiration_days must be a whole number of at least 30."
  }
}

variable "tags" {
  type        = map(string)
  description = "Common ownership, environment, cost, and governance tags."
  default     = {}
}
