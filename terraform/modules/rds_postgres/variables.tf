# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Declares resilient PostgreSQL capacity, encryption, retention, observability, and deletion controls.

variable "name" {
  type        = string
  description = "Stable identifier for the database, proxy, subnet group, roles, and secrets."

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,52}$", var.name))
    error_message = "name must be 3-53 lowercase alphanumeric or hyphen characters and start with a letter."
  }
}

variable "subnet_ids" {
  type        = list(string)
  description = "Private database subnet IDs spanning at least two Availability Zones."

  validation {
    condition     = length(var.subnet_ids) >= 2 && alltrue([for id in var.subnet_ids : can(regex("^subnet-[0-9a-f]+$", id))])
    error_message = "subnet_ids must contain at least two valid subnet IDs."
  }
}

variable "security_group_ids" {
  type        = list(string)
  description = "Security groups attached to the RDS instance and proxy."

  validation {
    condition     = length(var.security_group_ids) > 0 && alltrue([for id in var.security_group_ids : can(regex("^sg-[0-9a-f]+$", id))])
    error_message = "security_group_ids must contain at least one valid security-group ID."
  }
}

variable "kms_key_arn" {
  type        = string
  description = "Customer-managed KMS key ARN used by RDS, Performance Insights, and Secrets Manager."

  validation {
    condition     = can(regex("^arn:[^:]+:kms:[^:]+:[0-9]{12}:key/", var.kms_key_arn))
    error_message = "kms_key_arn must be a valid KMS key ARN."
  }
}

variable "engine_version" {
  type        = string
  description = "PostgreSQL engine major or major.minor version."
  default     = "17"

  validation {
    condition     = can(regex("^[0-9]+(\\.[0-9]+)?$", var.engine_version))
    error_message = "engine_version must be a numeric major or major.minor version."
  }
}

variable "instance_class" {
  type        = string
  description = "RDS instance class."

  validation {
    condition     = can(regex("^db\\.[a-z0-9]+\\.[a-z0-9]+$", var.instance_class))
    error_message = "instance_class must be an RDS class such as db.t4g.micro."
  }
}

variable "allocated_storage" {
  type        = number
  description = "Initial gp3 storage allocation in GiB."

  validation {
    condition     = floor(var.allocated_storage) == var.allocated_storage && var.allocated_storage >= 20
    error_message = "allocated_storage must be a whole number of at least 20 GiB."
  }
}

variable "max_allocated_storage" {
  type        = number
  description = "Maximum autoscaled storage in GiB; null uses five times the initial allocation."
  default     = null
  nullable    = true

  validation {
    condition     = var.max_allocated_storage == null || (floor(var.max_allocated_storage) == var.max_allocated_storage && var.max_allocated_storage >= var.allocated_storage)
    error_message = "max_allocated_storage must be null or a whole number at least as large as allocated_storage."
  }
}

variable "multi_az" {
  type        = bool
  description = "Maintain a synchronous standby in another Availability Zone."
  default     = true
}

variable "backup_retention_days" {
  type        = number
  description = "Number of days automated backups and point-in-time recovery are retained."
  default     = 30

  validation {
    condition     = floor(var.backup_retention_days) == var.backup_retention_days && var.backup_retention_days >= 1 && var.backup_retention_days <= 35
    error_message = "backup_retention_days must be a whole number between 1 and 35."
  }
}

variable "performance_insights_retention_days" {
  type        = number
  description = "Performance Insights retention. AWS accepts 7 or 731 days for this configuration."
  default     = 731

  validation {
    condition     = contains([7, 731], var.performance_insights_retention_days)
    error_message = "performance_insights_retention_days must be 7 or 731."
  }
}


variable "log_retention_days" {
  type        = number
  description = "CloudWatch retention for PostgreSQL and upgrade logs exported by RDS."
  default     = 365

  validation {
    condition     = floor(var.log_retention_days) == var.log_retention_days && var.log_retention_days >= 365
    error_message = "log_retention_days must be a whole number of at least 365."
  }
}

variable "monitoring_interval_seconds" {
  type        = number
  description = "Enhanced Monitoring interval in seconds."
  default     = 60

  validation {
    condition     = contains([1, 5, 10, 15, 30, 60], var.monitoring_interval_seconds)
    error_message = "monitoring_interval_seconds must be one of 1, 5, 10, 15, 30, or 60."
  }
}

variable "deletion_protection" {
  type        = bool
  description = "Reject accidental database deletion."
  default     = true
}

variable "apply_immediately" {
  type        = bool
  description = "Apply changes immediately instead of waiting for the maintenance window. Keep false for production."
  default     = false
}


variable "secret_recovery_window_days" {
  type        = number
  description = "Secrets Manager deletion recovery window for database and runtime secrets."
  default     = 30

  validation {
    condition     = floor(var.secret_recovery_window_days) == var.secret_recovery_window_days && var.secret_recovery_window_days >= 7 && var.secret_recovery_window_days <= 30
    error_message = "secret_recovery_window_days must be a whole number from 7 through 30."
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
