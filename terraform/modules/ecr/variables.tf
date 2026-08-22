# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Declares immutable encrypted repository names and rollback-image retention.

variable "name" {
  type        = string
  description = "Stable repository prefix."

  validation {
    condition     = can(regex("^[a-z0-9]+(?:[._/-][a-z0-9]+)*$", var.name))
    error_message = "name must use lowercase ECR-compatible repository characters."
  }
}

variable "repositories" {
  type        = set(string)
  description = "Logical repository suffixes managed by the module."

  validation {
    condition     = length(var.repositories) > 0 && alltrue([for name in var.repositories : can(regex("^[a-z0-9]+(?:[._/-][a-z0-9]+)*$", name))])
    error_message = "repositories must contain at least one lowercase ECR-compatible name."
  }
}

variable "kms_key_arn" {
  type        = string
  description = "Customer-managed KMS key ARN used for repository encryption."

  validation {
    condition     = can(regex("^arn:[^:]+:kms:[^:]+:[0-9]{12}:key/", var.kms_key_arn))
    error_message = "kms_key_arn must be a valid KMS key ARN."
  }
}

variable "retained_image_count" {
  type        = number
  description = "Number of recent images retained for rollback."
  default     = 30

  validation {
    condition     = floor(var.retained_image_count) == var.retained_image_count && var.retained_image_count >= 5 && var.retained_image_count <= 500
    error_message = "retained_image_count must be a whole number between 5 and 500."
  }
}

variable "force_delete" {
  type        = bool
  description = "Whether Terraform may delete a non-empty repository. Enable only for ephemeral environments."
  default     = false
}

variable "tags" {
  type        = map(string)
  description = "Common ownership, environment, cost, and governance tags."
  default     = {}
}
