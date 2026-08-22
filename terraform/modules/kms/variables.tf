# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Declares the customer-managed encryption key name, recovery window, and governance tags.

variable "name" {
  type        = string
  description = "KMS alias suffix and key-policy CloudTrail name scope."

  validation {
    condition     = length(trimspace(var.name)) >= 3 && length(var.name) <= 250 && can(regex("^[A-Za-z0-9/_-]+$", var.name))
    error_message = "name must contain 3-250 KMS alias-compatible characters."
  }
}

variable "deletion_window" {
  type        = number
  description = "Recovery window in days before scheduled key deletion becomes permanent."
  default     = 30

  validation {
    condition     = floor(var.deletion_window) == var.deletion_window && var.deletion_window >= 7 && var.deletion_window <= 30
    error_message = "deletion_window must be a whole number from 7 through 30."
  }
}

variable "tags" {
  type        = map(string)
  description = "Common ownership, environment, cost, and governance tags."
  default     = {}
}
