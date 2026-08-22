# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Declares the naming boundary this policy grants iam-responder's own execution identity permission to assume across every monitored account.

variable "monitored_role_name" {
  type        = string
  description = "Name of the role every monitored account grants Golem (see the golem_monitored_account_trust module's role_name, which must match exactly). This module grants sts:AssumeRole on arn:aws:iam::*:role/<monitored_role_name> -- a wildcard account ID is unavoidable here, since the whole point is reaching whichever accounts get registered with Golem after this policy is created, not a fixed list known at apply time."
  default     = "golem-iam-responder"

  validation {
    condition     = can(regex("^[A-Za-z0-9+=,.@_-]{1,64}$", var.monitored_role_name))
    error_message = "monitored_role_name must be 1-64 characters valid in an IAM role name."
  }
}

variable "name" {
  type        = string
  description = "Name of the standalone IAM policy this module creates."
  default     = "golem-iam-responder-assume-monitored-accounts"

  validation {
    condition     = length(trimspace(var.name)) >= 3 && length(var.name) <= 128
    error_message = "name must contain 3-128 characters."
  }
}

variable "tags" {
  type        = map(string)
  description = "Common ownership, environment, cost, and governance tags."
  default     = {}
}
