# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Declares CloudTrail encryption, retention, data-event scope, and Insights controls.

variable "name" {
  type        = string
  description = "Stable name for the trail, log bucket, log group, SNS topic, and IAM role."

  validation {
    condition     = can(regex("^[A-Za-z0-9._-]{3,128}$", var.name))
    error_message = "name must contain 3-128 CloudTrail-compatible characters."
  }
}

variable "kms_key_arn" {
  type        = string
  description = "Customer-managed KMS key ARN used by the trail's S3 bucket, SNS topic, and CloudWatch log group."

  validation {
    condition     = can(regex("^arn:[^:]+:kms:[^:]+:[0-9]{12}:key/", var.kms_key_arn))
    error_message = "kms_key_arn must be a valid KMS key ARN."
  }
}

variable "retention_days" {
  type        = number
  description = "Lifecycle expiration for trail log objects."
  default     = 365

  validation {
    condition     = floor(var.retention_days) == var.retention_days && var.retention_days >= 90
    error_message = "retention_days must be a whole number of at least 90."
  }
}

variable "access_log_bucket_id" {
  type        = string
  description = "Centralized S3 access-log bucket name that this trail's own bucket logs into."

  validation {
    condition     = length(trimspace(var.access_log_bucket_id)) >= 3
    error_message = "access_log_bucket_id must be a non-empty bucket name."
  }
}

variable "s3_data_event_bucket_arns" {
  type        = list(string)
  description = "Optional S3 bucket ARNs to capture object-level data events for. Empty disables data-event capture."
  default     = []
}

variable "enable_insights" {
  type        = bool
  description = "Enable CloudTrail Insights (unusual API call/error rate detection). Adds billable events."
  default     = false
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
