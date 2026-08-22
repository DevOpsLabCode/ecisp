# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Declares backup targets, encryption, schedule, retention, and optional immutable Vault Lock controls.

variable "name" {
  type        = string
  description = "Stable name for the backup vault and plan."

  validation {
    condition     = length(trimspace(var.name)) >= 3
    error_message = "name must contain at least three characters."
  }
}

variable "kms_key_arn" {
  type        = string
  description = "Customer-managed KMS key ARN used by the backup vault."

  validation {
    condition     = can(regex("^arn:[^:]+:kms:[^:]+:[0-9]{12}:key/", var.kms_key_arn))
    error_message = "kms_key_arn must be a valid KMS key ARN."
  }
}

variable "resource_arns" {
  type        = list(string)
  description = "Protected resource ARNs selected by the AWS Backup plan."

  validation {
    condition     = length(var.resource_arns) > 0 && alltrue([for arn in var.resource_arns : startswith(arn, "arn:")])
    error_message = "resource_arns must contain at least one ARN."
  }
}

variable "schedule_expression" {
  type        = string
  description = "AWS Backup cron expression for the recurring backup window."
  default     = "cron(0 5 ? * * *)"

  validation {
    condition     = can(regex("^(cron|rate)\\(", var.schedule_expression))
    error_message = "schedule_expression must be an AWS cron(...) or rate(...) expression."
  }
}

variable "minimum_retention_days" {
  type        = number
  description = "Normal recovery-point deletion age and, when enabled, Vault Lock minimum retention."
  default     = 35

  validation {
    condition     = floor(var.minimum_retention_days) == var.minimum_retention_days && var.minimum_retention_days >= 1
    error_message = "minimum_retention_days must be a positive whole number."
  }
}

variable "maximum_retention_days" {
  type        = number
  description = "Maximum recovery-point retention accepted by Vault Lock."
  default     = 3650

  validation {
    condition     = floor(var.maximum_retention_days) == var.maximum_retention_days && var.maximum_retention_days >= var.minimum_retention_days
    error_message = "maximum_retention_days must be a whole number greater than or equal to minimum_retention_days."
  }
}

variable "cold_storage_after_days" {
  type        = number
  description = "Days before eligible recovery points move to cold storage; null disables transition."
  default     = null
  nullable    = true

  validation {
    condition     = var.cold_storage_after_days == null || (floor(var.cold_storage_after_days) == var.cold_storage_after_days && var.cold_storage_after_days >= 0)
    error_message = "cold_storage_after_days must be null or a non-negative whole number."
  }
}

variable "enable_vault_lock" {
  type        = bool
  description = "Enable Compliance-mode Vault Lock. Recommended for production, but intentionally optional and defaulted off for a first-time deploy since it is irreversible once locked (see terraform/README.md)."
  default     = false
}

variable "vault_lock_changeable_for_days" {
  type        = number
  description = "Grace period before Vault Lock becomes immutable compliance mode."
  default     = 3

  validation {
    condition     = floor(var.vault_lock_changeable_for_days) == var.vault_lock_changeable_for_days && var.vault_lock_changeable_for_days >= 3
    error_message = "AWS Backup Vault Lock requires at least a three-day changeable period."
  }
}

variable "permissions_boundary_arn" {
  type        = string
  description = "AWS-managed PowerUserAccess policy ARN used as the permissions boundary for every workload IAM role."

  validation {
    condition     = can(regex("^arn:[^:]+:iam::aws:policy/PowerUserAccess$", var.permissions_boundary_arn))
    error_message = "permissions_boundary_arn must be the partition-correct AWS-managed PowerUserAccess policy ARN."
  }
}

variable "tags" {
  type        = map(string)
  description = "Common ownership, environment, cost, and governance tags."
  default     = {}
}

check "backup_lifecycle" {
  assert {
    condition     = var.cold_storage_after_days == null || var.cold_storage_after_days + 90 <= var.minimum_retention_days
    error_message = "Cold-stored recovery points must remain retained for at least 90 additional days."
  }
}

check "vault_lock_retention" {
  assert {
    condition     = !var.enable_vault_lock || var.minimum_retention_days >= 365
    error_message = "Compliance Vault Lock requires at least 365 days of minimum retention in this framework."
  }
}
