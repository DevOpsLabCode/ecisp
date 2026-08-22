# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Verifies trail configuration, dynamic block toggles, and validation logic this module produces, entirely
# offline. data.aws_iam_policy_document.logs and .notifications both interpolate not-yet-created resource ARNs
# (aws_s3_bucket.logs.arn, aws_sns_topic.notifications.arn), which are unknown under command = plan without a real
# AWS apply -- these tests instead cover the resource-level configuration this module controls directly (same
# constraint documented in modules/access_logs/tests).

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
  name                     = "golem-dev"
  kms_key_arn              = "arn:aws:kms:us-east-1:111111111111:key/abcd1234-0000-0000-0000-000000000000"
  access_log_bucket_id     = "golem-dev-111111111111-access-logs"
  permissions_boundary_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

run "trail_is_multi_region_with_log_file_validation" {
  command = plan

  assert {
    condition     = aws_cloudtrail.this.is_multi_region_trail == true
    error_message = "trail must be multi-region"
  }

  assert {
    condition     = aws_cloudtrail.this.enable_log_file_validation == true
    error_message = "log file validation must be enabled"
  }

  assert {
    condition     = aws_cloudtrail.this.include_global_service_events == true
    error_message = "global service events must be included"
  }
}

run "no_s3_data_events_by_default" {
  command = plan

  assert {
    condition     = length(aws_cloudtrail.this.event_selector[0].data_resource) == 0
    error_message = "no s3_data_event_bucket_arns should mean no data_resource block"
  }
}

run "s3_data_events_captured_when_bucket_arns_supplied" {
  command = plan

  variables {
    s3_data_event_bucket_arns = ["arn:aws:s3:::golem-dev-111111111111-media"]
  }

  assert {
    condition     = length(aws_cloudtrail.this.event_selector[0].data_resource) == 1
    error_message = "supplying s3_data_event_bucket_arns should add a data_resource block"
  }
}

run "no_insights_by_default" {
  command = plan

  assert {
    condition     = length(aws_cloudtrail.this.insight_selector) == 0
    error_message = "enable_insights defaults to false and should create no insight_selector blocks"
  }
}

run "insights_enabled_creates_both_selectors" {
  command = plan

  variables {
    enable_insights = true
  }

  assert {
    condition     = length(aws_cloudtrail.this.insight_selector) == 2
    error_message = "enable_insights=true should create both ApiCallRateInsight and ApiErrorRateInsight"
  }
}

run "retention_over_90_days_adds_the_glacier_transition" {
  command = plan

  variables {
    retention_days = 365
  }

  assert {
    condition     = length(aws_s3_bucket_lifecycle_configuration.logs.rule[0].transition) == 1
    error_message = "retention_days > 90 should add the GLACIER_IR transition"
  }
}

run "retention_at_90_days_omits_the_transition" {
  command = plan

  variables {
    retention_days = 90
  }

  assert {
    condition     = length(aws_s3_bucket_lifecycle_configuration.logs.rule[0].transition) == 0
    error_message = "retention_days <= 90 must omit the transition (S3 rejects transition-after-expiration ordering)"
  }
}

run "rejects_a_retention_below_90_days" {
  command = plan

  variables {
    retention_days = 30
  }

  expect_failures = [var.retention_days]
}
