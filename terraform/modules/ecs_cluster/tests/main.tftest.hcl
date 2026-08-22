# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Verifies the ECS cluster and Exec logging configuration this module produces, entirely offline.

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

run "cluster_has_enhanced_container_insights" {
  command = plan

  assert {
    condition     = aws_ecs_cluster.this.name == "golem-dev"
    error_message = "cluster name should equal var.name"
  }

  assert {
    condition     = [for s in aws_ecs_cluster.this.setting : s.value if s.name == "containerInsights"][0] == "enhanced"
    error_message = "containerInsights setting should be enhanced"
  }
}

run "exec_logging_is_encrypted_with_the_supplied_key" {
  command = plan

  assert {
    condition     = aws_cloudwatch_log_group.exec.kms_key_id == "arn:aws:kms:us-east-1:111111111111:key/abcd1234-0000-0000-0000-000000000000"
    error_message = "ECS Exec log group must be encrypted with the supplied KMS key"
  }

  assert {
    condition     = aws_cloudwatch_log_group.exec.name == "/aws/ecs/golem-dev/exec"
    error_message = "exec log group name should be /aws/ecs/<name>/exec"
  }
}

run "rejects_log_retention_below_365_days" {
  command = plan

  variables {
    log_retention_days = 30
  }

  expect_failures = [var.log_retention_days]
}
