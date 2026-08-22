# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Declares the input contract for the security Terraform module.

variable "name" {
  type        = string
  description = "Stable name prefix used for security-group names and tags."

  validation {
    condition     = trimspace(var.name) != "" && length(var.name) <= 200
    error_message = "name must be non-empty and no longer than 200 characters."
  }
}

variable "vpc_id" {
  type        = string
  description = "ID of the VPC that owns every security group."

  validation {
    condition     = can(regex("^vpc-[0-9a-f]+$", var.vpc_id))
    error_message = "vpc_id must be an AWS VPC ID."
  }
}

variable "vpc_cidr" {
  type        = string
  description = "Private VPC CIDR used to constrain east-west egress rules."

  validation {
    condition     = can(cidrnetmask(var.vpc_cidr))
    error_message = "vpc_cidr must be a valid IPv4 CIDR block."
  }
}

variable "app_port" {
  type        = number
  description = "Application TCP port allowed between the ALB and ECS tasks."
  default     = 8000

  validation {
    condition     = var.app_port >= 1 && var.app_port <= 65535
    error_message = "app_port must be a valid TCP port."
  }
}

variable "tags" {
  type        = map(string)
  description = "Common ownership, environment, cost, and governance tags."
  default     = {}
}
