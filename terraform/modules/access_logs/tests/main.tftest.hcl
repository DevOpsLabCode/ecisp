# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Verifies bucket configuration and validation logic this module produces, entirely offline. The bucket
# policy document (data.aws_iam_policy_document.this) interpolates aws_s3_bucket.this.arn, which is unknown until
# apply, so its resolved JSON can't be asserted on under command = plan without a real AWS apply -- these tests
# instead cover the resource-level configuration this module controls directly.

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

variables {
  name = "golem-dev-111111111111-access-logs"
}

run "bucket_blocks_all_public_access_and_enables_versioning" {
  command = plan

  assert {
    condition = (
      aws_s3_bucket_public_access_block.this.block_public_acls &&
      aws_s3_bucket_public_access_block.this.block_public_policy &&
      aws_s3_bucket_public_access_block.this.ignore_public_acls &&
      aws_s3_bucket_public_access_block.this.restrict_public_buckets
    )
    error_message = "every public-access-block control must be enabled"
  }

  assert {
    condition     = aws_s3_bucket_versioning.this.versioning_configuration[0].status == "Enabled"
    error_message = "bucket versioning must be enabled"
  }
}

run "lifecycle_retains_current_objects_for_the_configured_days" {
  command = plan

  assert {
    condition     = aws_s3_bucket_lifecycle_configuration.this.rule[0].expiration[0].days == 365
    error_message = "default retention_days should be 365"
  }
}

run "force_destroy_defaults_to_false" {
  command = plan

  assert {
    condition     = aws_s3_bucket.this.force_destroy == false
    error_message = "force_destroy should default to false"
  }
}

run "force_destroy_can_be_enabled_for_dev" {
  command = plan

  variables {
    force_destroy = true
  }

  assert {
    condition     = aws_s3_bucket.this.force_destroy == true
    error_message = "force_destroy should be true when explicitly set"
  }
}

run "rejects_a_bucket_name_with_uppercase_characters" {
  command = plan

  variables {
    name = "Golem-Dev-Access-Logs"
  }

  expect_failures = [var.name]
}

run "rejects_a_retention_below_365_days" {
  command = plan

  variables {
    retention_days = 30
  }

  expect_failures = [var.retention_days]
}
