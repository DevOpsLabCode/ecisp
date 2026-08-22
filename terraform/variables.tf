# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Declares configurable environment, networking, scaling, TLS, and observability inputs for the root stack.
# Reading guide: Each comment explains why the following Terraform block exists.

# Input `project_name`: Stable project prefix used to name and tag shared AWS resources.
variable "project_name" {
  type        = string
  description = "Stable lowercase project prefix used in AWS resource names and account-foundation contracts."
  default     = "golem"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", var.project_name))
    error_message = "project_name must be 3-63 lowercase alphanumeric or hyphen characters."
  }
}
# Input `environment`: Deployment environment name.
variable "environment" {
  type = string
  validation {
    condition     = contains(["dev", "prod"], var.environment)
    error_message = "environment must be dev or prod"
  }
}
# Input `aws_region`: AWS region in which every resource in this stack is created.
variable "aws_region" {
  type        = string
  description = "AWS region in which every resource in this stack is created."
  default     = "us-east-1"

  validation {
    condition     = can(regex("^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$", var.aws_region))
    error_message = "aws_region must be a valid AWS region name."
  }
}
# Input `domain_name`: Optional fully qualified DNS name the operator has manually pointed at the ALB (see
# modules/alb's README and this file's certificate_arn -- Route 53 automation is out of scope for V1, so DNS is a
# manual, one-time step the operator performs outside Terraform). Used only to compute application_url; does not
# create any DNS or ACM resource.
variable "domain_name" {
  type        = string
  description = "Optional custom domain the operator has manually pointed at the ALB. Purely informational for application_url; creates no DNS or ACM resources."
  default     = ""
}
# Input `certificate_arn`: Optional regional ACM certificate for the ALB's HTTPS listener. See modules/alb's README
# and terraform/README.md's ALB/certificate decision: null runs Golem V1's documented HTTP-only trial fallback.
variable "certificate_arn" {
  type        = string
  description = "Optional regional ACM certificate ARN (in aws_region, covering domain_name) for the ALB's HTTPS listener. Null runs the HTTP-only V1 trial fallback -- see terraform/README.md."
  default     = null
  nullable    = true

  validation {
    condition     = var.certificate_arn == null || can(regex("^arn:[^:]+:acm:[^:]+:[0-9]{12}:certificate/", var.certificate_arn))
    error_message = "certificate_arn must be null or an ACM certificate ARN."
  }
}
# Input `vpc_cidr`: Private IPv4 CIDR allocated to the VPC; subnet CIDRs are derived from this range.
variable "vpc_cidr" {
  type = string
  validation {
    condition     = can(cidrnetmask(var.vpc_cidr))
    error_message = "vpc_cidr must be a valid IPv4 CIDR block"
  }
}
# Input `az_count`: Number of Availability Zones across which subnet tiers are created.
variable "az_count" {
  type    = number
  default = 2
  validation {
    condition     = var.az_count >= 2 && var.az_count <= 3
    error_message = "az_count must be 2 or 3"
  }
}
# Input `nat_gateway_per_az`: Whether each application Availability Zone receives its own NAT gateway for resilience.
variable "nat_gateway_per_az" {
  type    = bool
  default = false
}
# Input `backend_image`: ECR image URI and tag/digest launched by the golem-backend ECS task.
variable "backend_image" {
  type = string
  validation {
    condition     = trimspace(var.backend_image) != ""
    error_message = "backend_image must not be empty"
  }
}
# Input `backend_cpu`: Fargate CPU units reserved for each golem-backend task.
variable "backend_cpu" {
  type    = number
  default = 512
}
# Input `backend_memory`: Memory in MiB reserved for each golem-backend task.
variable "backend_memory" {
  type    = number
  default = 1024
}
# Input `backend_desired_count`: Steady-state number of golem-backend tasks.
variable "backend_desired_count" {
  type    = number
  default = 1
}
# Input `backend_rollback_enabled`: Allow golem-backend rollback only after the deploy process verifies a completed ECS deployment.
variable "backend_rollback_enabled" {
  type    = bool
  default = false
}
# Input `iam_responder_image`: ECR image URI and tag/digest launched by the golem-iam-responder ECS task.
variable "iam_responder_image" {
  type = string
  validation {
    condition     = trimspace(var.iam_responder_image) != ""
    error_message = "iam_responder_image must not be empty"
  }
}
# Input `iam_responder_cpu`: Fargate CPU units reserved for each golem-iam-responder task.
variable "iam_responder_cpu" {
  type    = number
  default = 256
}
# Input `iam_responder_memory`: Memory in MiB reserved for each golem-iam-responder task.
variable "iam_responder_memory" {
  type    = number
  default = 512
}
# Input `iam_responder_desired_count`: Steady-state number of golem-iam-responder tasks.
variable "iam_responder_desired_count" {
  type    = number
  default = 1
}
# Input `iam_responder_rollback_enabled`: Allow golem-iam-responder rollback only after the deploy process verifies a completed ECS deployment.
variable "iam_responder_rollback_enabled" {
  type    = bool
  default = false
}
# Input `allow_zero_capacity`: Permit services to start at zero tasks during staged image publication.
variable "allow_zero_capacity" {
  type    = bool
  default = false
}
# Input `db_instance_class`: RDS PostgreSQL compute and memory class.
variable "db_instance_class" {
  type    = string
  default = "db.t4g.micro"
}
# Input `db_allocated_storage`: Initial encrypted PostgreSQL storage allocation in GiB.
variable "db_allocated_storage" {
  type    = number
  default = 20
}
# Input `db_multi_az`: Create a synchronous standby in another Availability Zone for production resilience.
variable "db_multi_az" {
  type    = bool
  default = true
}
# Input `deletion_protection`: Whether the ALB and RDS instance reject accidental deletion.
variable "deletion_protection" {
  type    = bool
  default = true
}
# Input `cloudtrail_retention_days`: Number of days CloudTrail's own S3 log objects are retained.
variable "cloudtrail_retention_days" {
  type    = number
  default = 365
}
# Input `github_org`: GitHub organization used for resource-tag attribution. See terraform/global/account for the
# OIDC trust relationship this same org/repo pair feeds into.
variable "github_org" {
  type    = string
  default = "DevOpsLabCode"
}
# Input `github_repo`: GitHub repository used for resource-tag attribution.
variable "github_repo" {
  type    = string
  default = "golem"
}
# Input `alarm_email`: Email endpoint subscribed to the operational SNS alarm topic.
variable "alarm_email" {
  type        = string
  description = "Optional operational alert mailbox."
  default     = ""

  validation {
    condition     = var.alarm_email == "" || can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.alarm_email))
    error_message = "alarm_email must be empty or a syntactically valid email address."
  }
}
# Input `tags`: Common ownership, environment, cost, and governance tags applied to supported resources.
variable "tags" {
  type    = map(string)
  default = {}
}
variable "enable_backup_vault_lock" {
  type        = bool
  description = "Enable Compliance-mode AWS Backup Vault Lock. Defaults to false since it is irreversible once locked -- see modules/backup's README and terraform/README.md's Vault Lock decision."
  default     = false
}

variable "backup_retention_days" {
  type        = number
  description = "Recovery-point retention and Vault Lock minimum retention."
  default     = 35

  validation {
    condition     = floor(var.backup_retention_days) == var.backup_retention_days && var.backup_retention_days >= 1
    error_message = "backup_retention_days must be a positive whole number."
  }
}

variable "backup_max_retention_days" {
  type        = number
  description = "Maximum retention accepted by Vault Lock."
  default     = 3650

  validation {
    condition     = floor(var.backup_max_retention_days) == var.backup_max_retention_days && var.backup_max_retention_days >= var.backup_retention_days
    error_message = "backup_max_retention_days must be at least backup_retention_days."
  }
}

variable "backup_cold_storage_after_days" {
  type        = number
  description = "Days before AWS Backup cold storage transition; null disables transition."
  default     = null
  nullable    = true
}

variable "backup_vault_lock_changeable_days" {
  type        = number
  description = "Grace period before Compliance-mode Vault Lock becomes immutable."
  default     = 3
}
