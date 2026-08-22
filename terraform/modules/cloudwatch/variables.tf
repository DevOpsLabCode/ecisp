# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Declares encrypted operational alerting, workload identifiers, and configurable alarm thresholds.

variable "name" {
  type        = string
  description = "Stable prefix for alarms, the dashboard, and the SNS topic."

  validation {
    condition     = trimspace(var.name) != "" && length(var.name) <= 180
    error_message = "name must be non-empty and no longer than 180 characters."
  }
}

variable "alb_arn_suffix" {
  type        = string
  description = "Application Load Balancer ARN suffix used by CloudWatch dimensions."

  validation {
    condition     = startswith(var.alb_arn_suffix, "app/")
    error_message = "alb_arn_suffix must be an Application Load Balancer ARN suffix beginning with app/."
  }
}

variable "target_group_arn_suffix" {
  type        = string
  description = "ALB target-group ARN suffix used by health and latency alarms."

  validation {
    condition     = startswith(var.target_group_arn_suffix, "targetgroup/")
    error_message = "target_group_arn_suffix must begin with targetgroup/."
  }
}

variable "cluster_name" {
  type        = string
  description = "ECS cluster name."
}

variable "service_names" {
  type        = map(string)
  description = "Stable alarm keys mapped to ECS service names monitored for CPU and memory pressure (Golem: backend, iam_responder)."

  validation {
    condition     = length(var.service_names) > 0 && alltrue([for name in values(var.service_names) : trimspace(name) != ""])
    error_message = "service_names must contain at least one statically keyed, non-empty ECS service name."
  }
}

variable "db_identifier" {
  type        = string
  description = "RDS database identifier."
}

variable "sns_email" {
  type        = string
  description = "Optional email endpoint subscribed to the alarm topic. Confirmation is required by AWS."
  default     = ""

  validation {
    condition     = var.sns_email == "" || can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.sns_email))
    error_message = "sns_email must be empty or a syntactically valid email address."
  }
}

variable "kms_key_arn" {
  type        = string
  description = "Customer-managed KMS key used to encrypt the alarm SNS topic."

  validation {
    condition     = can(regex("^arn:[^:]+:kms:[^:]+:[0-9]{12}:key/", var.kms_key_arn))
    error_message = "kms_key_arn must be a KMS key ARN."
  }
}

variable "account_root_arn" {
  type        = string
  description = "Owning account root ARN used by the explicit SNS administration policy."

  validation {
    condition     = can(regex("^arn:[^:]+:iam::[0-9]{12}:root$", var.account_root_arn))
    error_message = "account_root_arn must be an AWS account root ARN."
  }
}

variable "thresholds" {
  description = "Operational thresholds. Values are intentionally configurable because traffic and instance sizes differ by environment."
  type = object({
    alb_5xx_count            = optional(number, 5)
    target_5xx_count         = optional(number, 5)
    target_response_time_p95 = optional(number, 2)
    ecs_cpu_percent          = optional(number, 80)
    ecs_memory_percent       = optional(number, 80)
    rds_cpu_percent          = optional(number, 80)
    rds_free_storage_bytes   = optional(number, 5368709120)
  })
  default = {}

  validation {
    condition = (
      var.thresholds.alb_5xx_count >= 0 &&
      var.thresholds.target_5xx_count >= 0 &&
      var.thresholds.target_response_time_p95 > 0 &&
      var.thresholds.ecs_cpu_percent > 0 && var.thresholds.ecs_cpu_percent <= 100 &&
      var.thresholds.ecs_memory_percent > 0 && var.thresholds.ecs_memory_percent <= 100 &&
      var.thresholds.rds_cpu_percent > 0 && var.thresholds.rds_cpu_percent <= 100 &&
      var.thresholds.rds_free_storage_bytes > 0
    )
    error_message = "thresholds must use non-negative counts/durations/storage and percentages between 0 and 100."
  }
}

variable "tags" {
  type        = map(string)
  description = "Common ownership, environment, cost, and governance tags."
  default     = {}
}
