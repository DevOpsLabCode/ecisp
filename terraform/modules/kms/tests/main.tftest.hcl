# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Verifies the KMS key policy and alias this module produces, entirely offline -- aws_iam_policy_document is always computed locally by the provider, so overriding only the one data source that needs a genuine API call (aws_caller_identity) keeps the real policy logic under test.

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_region_validation      = true
}

override_data {
  target = data.aws_caller_identity.current
  values = {
    account_id = "111111111111"
  }
}

run "creates_key_and_alias_with_expected_name" {
  command = plan

  variables {
    name = "golem-dev"
  }

  assert {
    condition     = aws_kms_alias.this.name == "alias/golem-dev"
    error_message = "alias name should be alias/<name>"
  }

  assert {
    condition     = aws_kms_key.this.enable_key_rotation == true
    error_message = "key rotation must always be enabled"
  }

  assert {
    condition     = aws_kms_key.this.deletion_window_in_days == 30
    error_message = "default deletion_window should be 30"
  }
}

run "key_policy_grants_root_full_administration" {
  command = plan

  variables {
    name = "golem-dev"
  }

  assert {
    condition     = jsondecode(data.aws_iam_policy_document.this.json).Statement[0].Sid == "EnableAccountAdministration"
    error_message = "expected the account-administration statement first"
  }

  assert {
    condition     = jsondecode(data.aws_iam_policy_document.this.json).Statement[0].Principal.AWS == "arn:aws:iam::111111111111:root"
    error_message = "administration statement must name the exact account root, not a wildcard"
  }
}

run "custom_deletion_window_is_honored" {
  command = plan

  variables {
    name            = "golem-dev"
    deletion_window = 14
  }

  assert {
    condition     = aws_kms_key.this.deletion_window_in_days == 14
    error_message = "custom deletion_window should be honored"
  }
}

run "rejects_a_deletion_window_below_seven_days" {
  command = plan

  variables {
    name            = "golem-dev"
    deletion_window = 3
  }

  expect_failures = [var.deletion_window]
}

run "rejects_an_empty_name" {
  command = plan

  variables {
    name = ""
  }

  expect_failures = [var.name]
}
