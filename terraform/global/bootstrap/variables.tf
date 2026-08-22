# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Declares the protected remote-state bootstrap contract for account, dev, and prod roots.

variable "aws_region" {
  type        = string
  description = "AWS region containing the S3 backend and KMS key."

  validation {
    condition     = can(regex("^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$", var.aws_region))
    error_message = "aws_region must be a valid AWS region name."
  }
}

variable "environment" {
  type        = string
  description = "Backend ownership scope: account foundation, development, or production."

  validation {
    condition     = contains(["account", "dev", "prod"], var.environment)
    error_message = "environment must be account, dev, or prod."
  }
}

variable "project_name" {
  type        = string
  description = "Stable lowercase project prefix used in globally unique state resource names."
  default     = "golem"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", var.project_name))
    error_message = "project_name must contain 3-63 lowercase alphanumeric or hyphen characters."
  }
}
