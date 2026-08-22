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

run "rejects_a_repository_name_with_invalid_characters" {
  command = plan

  variables {
    repositories = ["Backend"]
  }

  expect_failures = [var.repositories]
}

run "rejects_a_name_with_invalid_characters" {
  command = plan

  variables {
    name = "Golem_Dev"
  }

  expect_failures = [var.name]
}

run "rejects_a_kms_key_arn_that_is_not_a_kms_key_arn" {
  command = plan

  variables {
    kms_key_arn = "arn:aws:iam::111111111111:role/not-a-kms-key"
  }

  expect_failures = [var.kms_key_arn]
}

run "custom_retained_image_count_is_honored" {
  command = plan

  variables {
    retained_image_count = 60
  }

  assert {
    condition     = jsondecode(aws_ecr_lifecycle_policy.this["backend"].policy).rules[0].selection.countNumber == 60
    error_message = "custom retained_image_count should be honored"
  }
}

run "rejects_a_retained_image_count_above_five_hundred" {
  command = plan

  variables {
    retained_image_count = 501
  }

  expect_failures = [var.retained_image_count]
}

run "output_repository_urls_and_arns_reflect_the_created_repositories" {
  command = apply

  override_resource {
    target = aws_ecr_repository.this["backend"]
    values = {
      repository_url = "111111111111.dkr.ecr.us-east-1.amazonaws.com/golem-dev-backend"
      arn             = "arn:aws:ecr:us-east-1:111111111111:repository/golem-dev-backend"
    }
  }

  override_resource {
    target = aws_ecr_repository.this["iam-responder"]
    values = {
      repository_url = "111111111111.dkr.ecr.us-east-1.amazonaws.com/golem-dev-iam-responder"
      arn             = "arn:aws:ecr:us-east-1:111111111111:repository/golem-dev-iam-responder"
    }
  }

  override_resource {
    target = aws_ecr_lifecycle_policy.this
    values = {
      id = "mock-lifecycle-policy"
    }
  }

  assert {
    condition     = output.repository_urls["backend"] == "111111111111.dkr.ecr.us-east-1.amazonaws.com/golem-dev-backend"
    error_message = "repository_urls output must map each repository suffix to its push/pull URL"
  }

  assert {
    condition     = contains(output.repository_arns, "arn:aws:ecr:us-east-1:111111111111:repository/golem-dev-iam-responder")
    error_message = "repository_arns output must contain each repository's ARN"
  }
}
