# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Declares the encrypted Golem fleet-credential secret and deletion-recovery controls.

variable "name" {
  type        = string
  description = "Secret path prefix."

  validation {
    condition     = length(trimspace(var.name)) >= 3 && length(var.name) <= 480
    error_message = "name must contain 3-480 characters."
  }
}

variable "kms_key_arn" {
  type        = string
  description = "Customer-managed KMS key ARN used to encrypt the secret."

  validation {
    condition     = can(regex("^arn:[^:]+:kms:[^:]+:[0-9]{12}:key/", var.kms_key_arn))
    error_message = "kms_key_arn must be a valid KMS key ARN."
  }
}

variable "recovery_window_in_days" {
  type        = number
  description = "Secrets Manager deletion recovery window."
  default     = 30

  validation {
    condition     = floor(var.recovery_window_in_days) == var.recovery_window_in_days && var.recovery_window_in_days >= 7 && var.recovery_window_in_days <= 30
    error_message = "recovery_window_in_days must be a whole number from 7 through 30."
  }
}

variable "tags" {
  type        = map(string)
  description = "Common ownership, environment, cost, and governance tags."
  default     = {}
}
