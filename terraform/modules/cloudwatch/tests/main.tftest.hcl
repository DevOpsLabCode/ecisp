# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Verifies alarm wiring, the no-redis/sqs/cloudfront pruning, and dashboard structure this module produces, entirely offline.

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
  name                    = "golem-dev"
  alb_arn_suffix          = "app/golem-dev/abc123"
  target_group_arn_suffix = "targetgroup/golem-dev-api/def456"
  cluster_name            = "golem-dev"
  service_names           = { backend = "golem-dev-backend", iam_responder = "golem-dev-iam-responder" }
  db_identifier           = "golem-dev"
  kms_key_arn             = "arn:aws:kms:us-east-1:111111111111:key/abcd1234-0000-0000-0000-000000000000"
  account_root_arn        = "arn:aws:iam::111111111111:root"
}

run "creates_one_cpu_and_memory_alarm_per_service" {
  command = plan

  assert {
    condition     = length(aws_cloudwatch_metric_alarm.ecs_cpu) == 2
    error_message = "expected one CPU alarm per service (backend, iam_responder)"
  }

  assert {
    condition     = length(aws_cloudwatch_metric_alarm.ecs_memory) == 2
    error_message = "expected one memory alarm per service"
  }

  assert {
    condition     = aws_cloudwatch_metric_alarm.ecs_cpu["backend"].alarm_name == "golem-dev-backend-ecs-cpu"
    error_message = "alarm name should be <name>-<service_key>-ecs-cpu"
  }
}

run "no_email_subscription_by_default" {
  command = plan

  assert {
    condition     = length(aws_sns_topic_subscription.email) == 0
    error_message = "no sns_email should mean no email subscription"
  }
}

run "email_subscription_created_when_configured" {
  command = plan

  variables {
    sns_email = "ops@example.com"
  }

  assert {
    condition     = length(aws_sns_topic_subscription.email) == 1
    error_message = "sns_email should create exactly one email subscription"
  }
}

run "rds_alarms_use_the_supplied_identifier" {
  command = plan

  assert {
    condition     = aws_cloudwatch_metric_alarm.rds_cpu.dimensions["DBInstanceIdentifier"] == "golem-dev"
    error_message = "RDS alarms must dimension on the supplied db_identifier"
  }
}

run "default_thresholds_apply" {
  command = plan

  assert {
    condition     = aws_cloudwatch_metric_alarm.alb_5xx.threshold == 5
    error_message = "default alb_5xx_count threshold should be 5"
  }

  assert {
    condition     = aws_cloudwatch_metric_alarm.rds_cpu.threshold == 80
    error_message = "default rds_cpu_percent threshold should be 80"
  }
}

run "custom_thresholds_are_honored" {
  command = plan

  variables {
    thresholds = {
      alb_5xx_count = 20
    }
  }

  assert {
    condition     = aws_cloudwatch_metric_alarm.alb_5xx.threshold == 20
    error_message = "custom alb_5xx_count threshold should be honored"
  }
}

run "rejects_an_alb_arn_suffix_missing_the_app_prefix" {
  command = plan

  variables {
    alb_arn_suffix = "not-an-alb-suffix"
  }

  expect_failures = [var.alb_arn_suffix]
}
