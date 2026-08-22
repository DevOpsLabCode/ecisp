# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Declares the trusted principal, naming boundary, and safeguards this account grants to Golem's IAM-revocation component.

variable "trusted_principal_arn" {
  type        = string
  description = "Exact IAM role ARN of Golem's iam-responder execution identity in its own security-tooling account -- never an account root, so this trust can't be satisfied by any other principal in that account."

  validation {
    condition     = can(regex("^arn:[^:]+:iam::[0-9]{12}:role/", var.trusted_principal_arn))
    error_message = "trusted_principal_arn must be an IAM role ARN (arn:...:iam::<account>:role/...)."
  }
}

variable "external_id" {
  type        = string
  description = "Optional STS external ID required on every AssumeRole call into this role. Strongly recommended -- see the module README's confused-deputy note -- but left optional since choosing a shared-vs-per-account external ID scheme is an operator decision this module doesn't make for you."
  default     = ""
  sensitive   = true
}

variable "role_name" {
  type        = string
  description = "Name of the IAM role Golem's iam-responder assumes into this account. Must match the role_name every monitored account uses -- iam-responder's own execution policy (see the golem_iam_responder_execution module) grants sts:AssumeRole on arn:aws:iam::*:role/<role_name>, a single pattern applied across every monitored account."
  default     = "golem-iam-responder"

  validation {
    condition     = can(regex("^[A-Za-z0-9+=,.@_-]{1,64}$", var.role_name))
    error_message = "role_name must be 1-64 characters valid in an IAM role name."
  }
}

variable "monitored_role_name_prefix" {
  type        = string
  description = "Naming convention this account's own workload roles must follow to be revocable by Golem. Golem's PutRolePolicy/DeleteRolePolicy grant is scoped to arn:aws:iam::<this account>:role/<prefix>* -- even a fully compromised iam-responder can only ever touch roles matching this prefix, never arbitrary IAM roles in this account."
  default     = "golem-monitored-"

  validation {
    condition     = can(regex("^[A-Za-z0-9+=,.@_-]+$", var.monitored_role_name_prefix))
    error_message = "monitored_role_name_prefix must contain only characters valid in an IAM role name."
  }
}

variable "permissions_boundary_arn" {
  type        = string
  description = "Optional permissions boundary ARN applied to the created role. Left unset by default -- set this to whatever policy this account already uses to bound workload roles, if any."
  default     = null
}

variable "tags" {
  type        = map(string)
  description = "Common ownership, environment, cost, and governance tags."
  default     = {}
}
