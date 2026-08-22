# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Verifies repository creation, immutability, and lifecycle policy this module produces, entirely offline.

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_region_validation      = true
}

variables {
  name         = "golem-dev"
  repositories = ["backend", "iam-responder"]
  kms_key_arn  = "arn:aws:kms:us-east-1:111111111111:key/abcd1234-0000-0000-0000-000000000000"
}

run "creates_one_repository_per_declared_suffix" {
  command = plan

  assert {
    condition     = length(aws_ecr_repository.this) == 2
    error_message = "expected exactly two repositories for [backend, iam-responder]"
  }

  assert {
    condition     = aws_ecr_repository.this["backend"].name == "golem-dev-backend"
    error_message = "backend repository should be named <name>-backend"
  }

  assert {
    condition     = aws_ecr_repository.this["iam-responder"].name == "golem-dev-iam-responder"
    error_message = "iam-responder repository should be named <name>-iam-responder"
  }
}

run "repositories_use_immutable_tags_and_scan_on_push" {
  command = plan

  assert {
    condition     = alltrue([for r in aws_ecr_repository.this : r.image_tag_mutability == "IMMUTABLE"])
    error_message = "every repository must use IMMUTABLE tags"
  }

  assert {
    condition     = alltrue([for r in aws_ecr_repository.this : r.image_scanning_configuration[0].scan_on_push == true])
    error_message = "every repository must scan on push"
  }
}

run "lifecycle_policy_expires_beyond_the_retained_image_count" {
  command = plan

  assert {
    condition     = jsondecode(aws_ecr_lifecycle_policy.this["backend"].policy).rules[0].selection.countNumber == 30
    error_message = "default retained_image_count should be 30"
  }
}

run "rejects_an_empty_repository_set" {
  command = plan

  variables {
    repositories = []
  }

  expect_failures = [var.repositories]
}
