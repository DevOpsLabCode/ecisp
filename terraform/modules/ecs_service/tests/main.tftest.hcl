# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Verifies task definitions, IAM scoping, load-balancer wiring, and check-block gates this module produces, entirely offline.

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
  name                      = "golem-dev-backend"
  cluster_arn               = "arn:aws:ecs:us-east-1:111111111111:cluster/golem-dev"
  subnet_ids                = ["subnet-0123456789abcdef0", "subnet-0123456789abcdef1"]
  security_group_ids        = ["sg-0123456789abcdef0"]
  ecr_repository_arns       = ["arn:aws:ecr:us-east-1:111111111111:repository/golem-backend"]
  image                     = "111111111111.dkr.ecr.us-east-1.amazonaws.com/golem-backend:v1"
  cpu                       = 512
  memory                    = 1024
  desired_count             = 1
  kms_key_arn               = "arn:aws:kms:us-east-1:111111111111:key/abcd1234-0000-0000-0000-000000000000"
  queue_arn                 = ""
  queue_actions             = []
  object_storage_bucket_arn = null
  ses_identity_arn          = null
  enable_xray               = false
  permissions_boundary_arn  = "arn:aws:iam::aws:policy/PowerUserAccess"
}

run "exposed_backend_service_gets_a_port_mapping_and_health_check" {
  command = plan

  assert {
    condition     = length([for c in jsondecode(jsonencode(local.container_definitions)) : c if c.name == "golem-dev-backend"]) == 1
    error_message = "expected exactly one application container"
  }

  assert {
    condition     = aws_ecs_task_definition.this.family == "golem-dev-backend"
    error_message = "task family should equal var.name"
  }

  assert {
    condition     = length(aws_ecs_task_definition.this.container_definitions) > 0
    error_message = "container_definitions must not be empty"
  }
}

run "no_xray_sidecar_when_disabled" {
  command = plan

  assert {
    condition     = length(local.container_definitions) == 1
    error_message = "enable_xray=false should produce exactly one container definition (no xray-daemon sidecar)"
  }
}

run "xray_sidecar_present_when_enabled" {
  command = plan

  variables {
    enable_xray = true
  }

  assert {
    condition     = length(local.container_definitions) == 2
    error_message = "enable_xray=true should add the xray-daemon sidecar container"
  }
}

run "worker_style_service_has_no_port_mapping_or_load_balancer" {
  command = plan

  variables {
    name                = "golem-dev-iam-responder"
    expose_port         = false
    enable_health_check = false
    enable_autoscaling  = false
    target_group_arn    = null
  }

  assert {
    condition     = length(local.application_container.portMappings) == 0
    error_message = "expose_port=false must produce an empty portMappings list"
  }

  assert {
    condition     = length([for lb in aws_ecs_service.this.load_balancer : lb]) == 0
    error_message = "no target_group_arn means no load_balancer block should be generated"
  }

  assert {
    condition     = length(aws_appautoscaling_target.this) == 0
    error_message = "enable_autoscaling=false should create no autoscaling target"
  }
}

run "execution_role_is_scoped_to_declared_ecr_repos_and_log_group" {
  command = plan

  assert {
    condition     = jsondecode(aws_iam_role_policy.execution.policy).Statement[1].Resource[0] == "arn:aws:ecr:us-east-1:111111111111:repository/golem-backend"
    error_message = "execution role must scope PullApplicationImages to the declared ECR repository ARNs"
  }
}

run "target_group_without_expose_port_is_rejected_by_check" {
  command = plan

  variables {
    expose_port      = false
    target_group_arn = "arn:aws:elasticloadbalancing:us-east-1:111111111111:targetgroup/golem-dev/abc123"
  }

  expect_failures = [check.load_balancer_contract]
}

run "unsupported_cpu_memory_combination_is_rejected_by_check" {
  command = plan

  variables {
    cpu    = 256
    memory = 4096
  }

  expect_failures = [check.fargate_size]
}

run "rejects_an_empty_image" {
  command = plan

  variables {
    image = ""
  }

  expect_failures = [var.image]
}
