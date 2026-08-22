# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Verifies the assume-role policy this module produces, entirely offline -- a credential-free provider config is enough here, since this module has no data sources that need a real API call at all.

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_region_validation      = true
}

run "creates_policy_with_default_name" {
  command = plan

  assert {
    condition     = aws_iam_policy.assume_monitored_accounts.name == "golem-iam-responder-assume-monitored-accounts"
    error_message = "default policy name should be golem-iam-responder-assume-monitored-accounts"
  }
}

run "policy_grants_assume_role_on_the_default_monitored_role_name_across_any_account" {
  command = plan

  assert {
    condition     = jsondecode(data.aws_iam_policy_document.assume_monitored_accounts.json).Statement[0].Resource == "arn:*:iam::*:role/golem-iam-responder"
    error_message = "must grant sts:AssumeRole on arn:*:iam::*:role/golem-iam-responder by default"
  }

  assert {
    condition     = jsondecode(data.aws_iam_policy_document.assume_monitored_accounts.json).Statement[0].Action == "sts:AssumeRole"
    error_message = "the only granted action must be sts:AssumeRole"
  }
}

run "custom_monitored_role_name_is_reflected_in_the_resource_pattern" {
  command = plan

  variables {
    monitored_role_name = "golem-iam-responder-custom"
  }

  assert {
    condition     = jsondecode(data.aws_iam_policy_document.assume_monitored_accounts.json).Statement[0].Resource == "arn:*:iam::*:role/golem-iam-responder-custom"
    error_message = "custom monitored_role_name should be reflected in the resource pattern"
  }
}

run "custom_name_is_honored" {
  command = plan

  variables {
    name = "custom-policy-name"
  }

  assert {
    condition     = aws_iam_policy.assume_monitored_accounts.name == "custom-policy-name"
    error_message = "custom name should be honored"
  }
}

run "rejects_a_name_that_is_too_short" {
  command = plan

  variables {
    name = "ab"
  }

  expect_failures = [var.name]
}

run "rejects_a_monitored_role_name_with_invalid_characters" {
  command = plan

  variables {
    monitored_role_name = "bad role name!"
  }

  expect_failures = [var.monitored_role_name]
}

run "output_policy_arn_reflects_the_created_policy" {
  command = apply

  override_resource {
    target = aws_iam_policy.assume_monitored_accounts
    values = {
      arn = "arn:aws:iam::111111111111:policy/golem-iam-responder-assume-monitored-accounts"
    }
  }

  assert {
    condition     = output.policy_arn == "arn:aws:iam::111111111111:policy/golem-iam-responder-assume-monitored-accounts"
    error_message = "policy_arn output must reflect the created policy's ARN"
  }
}
