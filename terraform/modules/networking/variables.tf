# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Declares VPC addressing, Availability Zone spread, NAT resilience, encryption, and flow-log retention.

variable "name" {
  type        = string
  description = "Stable VPC, subnet, route, log-group, and IAM role name prefix."

  validation {
    condition     = length(trimspace(var.name)) >= 3 && length(var.name) <= 48
    error_message = "name must contain 3-48 characters."
  }
}

variable "cidr" {
  type        = string
  description = "IPv4 VPC CIDR from which public, application, and database subnets are derived."

  validation {
    condition     = can(cidrnetmask(var.cidr)) && tonumber(split("/", var.cidr)[1]) <= 20
    error_message = "cidr must be a valid IPv4 block with enough space for three subnet tiers (/20 or larger)."
  }
}

variable "az_count" {
  type        = number
  description = "Number of Availability Zones used by each subnet tier."

  validation {
    condition     = floor(var.az_count) == var.az_count && var.az_count >= 2 && var.az_count <= 3
    error_message = "az_count must be the whole number 2 or 3."
  }
}

variable "nat_gateway_per_az" {
  type        = bool
  description = "Create one NAT gateway per application Availability Zone instead of one shared development NAT gateway."
  default     = false
}

variable "kms_key_arn" {
  type        = string
  description = "Customer-managed KMS key used by the VPC flow-log group."

  validation {
    condition     = can(regex("^arn:[^:]+:kms:[^:]+:[0-9]{12}:key/", var.kms_key_arn))
    error_message = "kms_key_arn must be a valid KMS key ARN."
  }
}

variable "flow_log_retention_days" {
  type        = number
  description = "CloudWatch retention for accepted and rejected VPC flow records."
  default     = 365

  validation {
    condition     = floor(var.flow_log_retention_days) == var.flow_log_retention_days && var.flow_log_retention_days >= 365
    error_message = "flow_log_retention_days must be a whole number of at least 365."
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
