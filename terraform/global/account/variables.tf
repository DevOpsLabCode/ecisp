# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Declares the account-wide security foundation input contract.

variable "aws_region" {
  type        = string
  description = "AWS region in which regional account-security services are enabled."
  default     = "us-east-1"

  validation {
    condition     = can(regex("^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$", var.aws_region))
    error_message = "aws_region must be a valid AWS region name."
  }
}

variable "project_name" {
  type        = string
  description = "Stable project name used for tags and account-foundation resource names."
  default     = "golem"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", var.project_name))
    error_message = "project_name must be 3-63 lowercase alphanumeric or hyphen characters."
  }
}


variable "github_org" {
  type        = string
  description = "GitHub organization trusted to assume Terraform plan and apply roles."
  default     = "DevOpsLabCode"

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+$", var.github_org))
    error_message = "github_org contains unsupported characters."
  }
}

variable "github_repo" {
  type        = string
  description = "GitHub repository trusted to assume Terraform plan and apply roles."
  default     = "golem"

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+$", var.github_repo))
    error_message = "github_repo contains unsupported characters."
  }
}

variable "plan_branches" {
  type        = set(string)
  description = "Optional trusted branches allowed to assume the Terraform plan role when the job does not use a GitHub environment."
  default     = []

  validation {
    condition     = alltrue([for branch in var.plan_branches : trimspace(branch) != "" && branch != "*"])
    error_message = "plan_branches must contain only explicit branch names."
  }
}

variable "plan_environments" {
  type        = set(string)
  description = "Protected GitHub environments allowed to assume the read-only Terraform plan role."
  default     = ["dev"]

  validation {
    condition     = length(var.plan_environments) > 0 && alltrue([for environment in var.plan_environments : trimspace(environment) != "" && environment != "*"])
    error_message = "plan_environments must contain explicit environment names."
  }
}

variable "apply_branches" {
  type        = set(string)
  description = "Optional trusted branches allowed to assume the Terraform apply role when the job does not use a protected GitHub environment."
  default     = []

  validation {
    condition     = alltrue([for branch in var.apply_branches : trimspace(branch) != "" && branch != "*"])
    error_message = "apply_branches must contain only explicit branch names."
  }
}

variable "apply_environments" {
  type        = set(string)
  description = "Protected GitHub environment subjects allowed to assume the Terraform apply role."
  default     = ["dev", "prod"]

  validation {
    condition     = length(var.apply_environments) > 0 && alltrue([for environment in var.apply_environments : trimspace(environment) != "" && environment != "*"])
    error_message = "apply_environments must contain explicit environment names."
  }
}

variable "allow_plan_pull_requests" {
  type        = bool
  description = "Allow pull_request subjects to assume the plan role. Keep false for remote-state plans; a workflow should plan only after merge from the protected dev environment."
  default     = false
}

variable "guardduty_finding_frequency" {
  type        = string
  description = "Frequency at which GuardDuty publishes updated findings."
  default     = "FIFTEEN_MINUTES"

  validation {
    condition     = contains(["FIFTEEN_MINUTES", "ONE_HOUR", "SIX_HOURS"], var.guardduty_finding_frequency)
    error_message = "guardduty_finding_frequency must be FIFTEEN_MINUTES, ONE_HOUR, or SIX_HOURS."
  }
}

variable "enable_guardduty_organization_auto_enrollment" {
  type        = bool
  description = "Manage GuardDuty AWS Organizations auto-enrollment in this region. Enable only in the delegated GuardDuty administrator account."
  default     = false
}

variable "enable_guardduty_runtime_monitoring" {
  type        = bool
  description = "Enable GuardDuty Runtime Monitoring and automatic Fargate agent management."
  default     = true
}

variable "enable_enhanced_ecr_scanning" {
  type        = bool
  description = "Enable Inspector-backed continuous enhanced scanning for every ECR repository in the account."
  default     = true
}

variable "tags" {
  type        = map(string)
  description = "Additional account-foundation tags merged with required ownership tags."
  default     = {}
}
