# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Verifies vault/plan wiring, the Vault Lock default-off posture, and check-block gates this module produces, entirely offline.

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_region_validation      = true
}

variables {
  name                     = "golem-dev"
  kms_key_arn              = "arn:aws:kms:us-east-1:111111111111:key/abcd1234-0000-0000-0000-000000000000"
  resource_arns            = ["arn:aws:rds:us-east-1:111111111111:db:golem-dev"]
  permissions_boundary_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

run "vault_lock_is_off_by_default" {
  command = plan

  assert {
    condition     = var.enable_vault_lock == false
    error_message = "enable_vault_lock must default to false -- it is irreversible once locked (see README)"
  }

  assert {
    condition     = length(aws_backup_vault_lock_configuration.this) == 0
    error_message = "no Vault Lock configuration should be created by default"
  }
}

run "vault_lock_can_be_enabled_with_sufficient_retention" {
  command = plan

  variables {
    enable_vault_lock      = true
    minimum_retention_days = 365
  }

  assert {
    condition     = length(aws_backup_vault_lock_configuration.this) == 1
    error_message = "enable_vault_lock=true should create the Vault Lock configuration"
  }
}

run "vault_lock_with_insufficient_retention_is_rejected_by_check" {
  command = plan

  variables {
    enable_vault_lock      = true
    minimum_retention_days = 30
  }

  expect_failures = [check.vault_lock_retention]
}

run "backup_plan_targets_the_declared_resources" {
  command = plan

  assert {
    condition     = contains(aws_backup_selection.this.resources, "arn:aws:rds:us-east-1:111111111111:db:golem-dev")
    error_message = "backup selection must target the supplied resource_arns"
  }

  assert {
    condition     = [for r in aws_backup_plan.this.rule : r.lifecycle[0].delete_after][0] == 35
    error_message = "default minimum_retention_days should be 35"
  }
}

run "cold_storage_without_enough_headroom_is_rejected_by_check" {
  command = plan

  variables {
    cold_storage_after_days = 300
    minimum_retention_days  = 320
  }

  expect_failures = [check.backup_lifecycle]
}

run "rejects_empty_resource_arns" {
  command = plan

  variables {
    resource_arns = []
  }

  expect_failures = [var.resource_arns]
}
