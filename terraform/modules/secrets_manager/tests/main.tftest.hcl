# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Verifies the secret container and initial-value wiring this module produces, entirely offline.

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_region_validation      = true
}

variables {
  name        = "golem-dev"
  kms_key_arn = "arn:aws:kms:us-east-1:111111111111:key/abcd1234-0000-0000-0000-000000000000"
}

run "creates_secret_at_the_expected_path" {
  command = plan

  assert {
    condition     = aws_secretsmanager_secret.golem.name == "golem-dev/golem-secrets"
    error_message = "secret name should be <name>/golem-secrets"
  }

  assert {
    condition     = aws_secretsmanager_secret.golem.kms_key_id == "arn:aws:kms:us-east-1:111111111111:key/abcd1234-0000-0000-0000-000000000000"
    error_message = "secret must be encrypted with the supplied KMS key"
  }
}

run "generates_a_random_initial_api_key" {
  command = plan

  assert {
    condition     = random_password.iam_responder_api_key.length == 48
    error_message = "generated IAM_RESPONDER_API_KEY should be 48 characters"
  }
}

run "default_recovery_window_is_30_days" {
  command = plan

  assert {
    condition     = aws_secretsmanager_secret.golem.recovery_window_in_days == 30
    error_message = "default recovery_window_in_days should be 30"
  }
}

run "custom_recovery_window_is_honored" {
  command = plan

  variables {
    recovery_window_in_days = 7
  }

  assert {
    condition     = aws_secretsmanager_secret.golem.recovery_window_in_days == 7
    error_message = "custom recovery_window_in_days should be honored"
  }
}

run "rejects_a_recovery_window_below_seven_days" {
  command = plan

  variables {
    recovery_window_in_days = 3
  }

  expect_failures = [var.recovery_window_in_days]
}
