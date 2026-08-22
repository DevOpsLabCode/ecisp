# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Verifies bucket configuration, the bucket policy document, and outputs this module produces, entirely
# offline. The bucket policy document (data.aws_iam_policy_document.this) interpolates aws_s3_bucket.this.arn, which
# is unknown until apply -- most runs stay at command = plan and assert on resource-level configuration only, but the
# dedicated apply run below overrides every resource in the chain with known values (no real AWS call happens) so the
# resolved policy JSON and outputs can be asserted on too.

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

run "rejects_an_empty_alb_prefix" {
  command = plan

  variables {
    alb_prefix = "/"
  }

  expect_failures = [var.alb_prefix]
}

run "rejects_an_alb_prefix_starting_with_a_slash" {
  command = plan

  variables {
    alb_prefix = "/alb"
  }

  expect_failures = [var.alb_prefix]
}

run "rejects_a_noncurrent_version_expiration_below_30_days" {
  command = plan

  variables {
    noncurrent_version_expiration_days = 10
  }

  expect_failures = [var.noncurrent_version_expiration_days]
}

run "bucket_policy_and_outputs_reflect_the_created_bucket" {
  command = apply

  variables {
    alb_prefix = "custom-alb"
  }

  override_resource {
    target = aws_s3_bucket.this
    values = {
      id  = "golem-dev-111111111111-access-logs"
      arn = "arn:aws:s3:::golem-dev-111111111111-access-logs"
    }
  }

  override_resource {
    target = aws_s3_bucket_ownership_controls.this
    values = { id = "golem-dev-111111111111-access-logs" }
  }

  override_resource {
    target = aws_s3_bucket_public_access_block.this
    values = { id = "golem-dev-111111111111-access-logs" }
  }

  override_resource {
    target = aws_s3_bucket_versioning.this
    values = { id = "golem-dev-111111111111-access-logs" }
  }

  override_resource {
    target = aws_s3_bucket_server_side_encryption_configuration.this
    values = { id = "golem-dev-111111111111-access-logs" }
  }

  override_resource {
    target = aws_s3_bucket_lifecycle_configuration.this
    values = { id = "golem-dev-111111111111-access-logs" }
  }

  override_resource {
    target = aws_s3_bucket_policy.this
    values = { id = "golem-dev-111111111111-access-logs" }
  }

  assert {
    condition     = output.bucket_id == "golem-dev-111111111111-access-logs"
    error_message = "bucket_id output must reflect the created bucket's id"
  }

  assert {
    condition     = output.bucket_arn == "arn:aws:s3:::golem-dev-111111111111-access-logs"
    error_message = "bucket_arn output must reflect the created bucket's ARN"
  }

  assert {
    condition     = jsondecode(data.aws_iam_policy_document.this.json).Statement[0].Resource == "arn:aws:s3:::golem-dev-111111111111-access-logs/custom-alb/AWSLogs/111111111111/*"
    error_message = "ALB log delivery statement must scope to the custom alb_prefix and this account"
  }

  assert {
    condition     = jsondecode(data.aws_iam_policy_document.this.json).Statement[3].Sid == "DenyInsecureTransport"
    error_message = "expected the insecure-transport deny statement fourth"
  }

  assert {
    condition     = jsondecode(data.aws_iam_policy_document.this.json).Statement[3].Effect == "Deny"
    error_message = "insecure-transport statement must deny, not allow"
  }
}
