# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Creates IAM roles, logs, task definitions, services, autoscaling, secrets, sidecars, and optional load-balancer integration for API or worker workloads.
# Reading guide: Each comment explains why the following Terraform block exists.
# Vendored from demand-gig-engine/terraform/modules/ecs_service with no logic changes -- see terraform/README.md for the
# vendoring rationale. Golem's two services (golem-backend, golem-iam-responder) instantiate this module with the
# SQS/S3/SES/X-Ray integration toggles off or null rather than stripping this module's flexibility, since it is meant
# to be reused as-is.
# Read the active region for awslogs configuration inside generated container definitions.
data "aws_region" "current" {}
data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}

# Assemble least-privilege IAM statements and container-definition fragments once, then reuse them in task roles and task definitions.
locals {
  secret_arns = distinct([
    for value in values(var.secrets) : replace(value, "/:[^:]+::$/", "")
  ])

  # GuardDuty injects this AWS-owned sidecar into protected ECS Fargate tasks.
  # The US East (N. Virginia) repository account is published by AWS.
  guardduty_agent_repository_arn = "arn:${data.aws_partition.current.partition}:ecr:${data.aws_region.current.region}:593207742271:repository/aws-guardduty-agent-fargate"

  object_storage_statements = var.object_storage_bucket_arn == null ? [] : [
    {
      Effect   = "Allow"
      Action   = ["s3:DeleteObject", "s3:GetObject", "s3:PutObject"]
      Resource = "${var.object_storage_bucket_arn}/*"
    },
    {
      Effect   = "Allow"
      Action   = ["s3:ListBucket"]
      Resource = var.object_storage_bucket_arn
    },
    {
      Effect = "Allow"
      Action = [
        "kms:Decrypt",
        "kms:DescribeKey",
        "kms:Encrypt",
        "kms:GenerateDataKey",
      ]
      Resource = var.kms_key_arn
    },
  ]

  email_statements = var.ses_identity_arn == null ? [] : [
    {
      Effect   = "Allow"
      Action   = ["ses:SendEmail", "ses:SendRawEmail"]
      Resource = var.ses_identity_arn
    }
  ]

  tracing_statements = var.enable_xray ? [
    {
      Effect   = "Allow"
      Action   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
      Resource = "*"
    }
  ] : []

  queue_statements = length(var.queue_actions) == 0 ? [] : [
    {
      Effect   = "Allow"
      Action   = sort(tolist(var.queue_actions))
      Resource = var.queue_arn
    },
    {
      Effect   = "Allow"
      Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
      Resource = var.kms_key_arn
    },
  ]

  application_statements = concat(
    local.queue_statements,
    [
      {
        Effect = "Allow"
        Action = [
          "ssmmessages:CreateControlChannel",
          "ssmmessages:CreateDataChannel",
          "ssmmessages:OpenControlChannel",
          "ssmmessages:OpenDataChannel",
        ]
        Resource = "*"
      }
    ],
    local.email_statements,
    local.object_storage_statements,
    local.tracing_statements,
  )

  application_container = {
    name                   = var.name
    image                  = var.image
    essential              = true
    user                   = "app"
    privileged             = false
    readonlyRootFilesystem = true
    stopTimeout            = 30

    linuxParameters = {
      initProcessEnabled = true
      capabilities = {
        drop = ["ALL"]
      }
    }

    mountPoints = [
      {
        sourceVolume  = "tmp"
        containerPath = "/tmp"
        readOnly      = false
      }
    ]

    portMappings = var.expose_port ? [
      {
        containerPort = var.container_port
        protocol      = "tcp"
      }
    ] : []

    command = length(var.command) == 0 ? null : var.command

    environment = [
      for key, value in var.environment : {
        name  = key
        value = value
      }
    ]

    secrets = [
      for key, value in var.secrets : {
        name      = key
        valueFrom = value
      }
    ]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.this.name
        "awslogs-region"        = data.aws_region.current.region
        "awslogs-stream-prefix" = "ecs"
      }
    }
  }

  health_check = {
    healthCheck = {
      command = [
        "CMD-SHELL",
        "python -c 'import urllib.request; urllib.request.urlopen(\"http://localhost:${var.container_port}/api/health/\", timeout=3)' || exit 1",
      ]
      interval    = 30
      timeout     = 5
      retries     = 3
      startPeriod = 60
    }
  }

  xray_container = {
    name                   = "xray-daemon"
    image                  = var.xray_image
    essential              = false
    readonlyRootFilesystem = true
    user                   = "1337"

    portMappings = [
      {
        containerPort = 2000
        protocol      = "udp"
      }
    ]

    command = ["-o"]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.this.name
        "awslogs-region"        = data.aws_region.current.region
        "awslogs-stream-prefix" = "xray"
      }
    }
  }

  application_with_health = merge(
    local.application_container,
    var.enable_health_check ? local.health_check : {},
  )

  container_definitions = concat(
    [local.application_with_health],
    [for enabled in [var.enable_xray] : local.xray_container if enabled],
  )
}

# Build the shared ECS task trust policy used by both execution and application task roles.
data "aws_iam_policy_document" "assume" {
  # Allow ECS tasks, and no human principal, to assume the execution and application roles.
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

# Creates an IAM role with a narrowly defined trust relationship.
resource "aws_iam_role" "execution" {
  permissions_boundary = var.permissions_boundary_arn
  name                 = "${var.name}-exec"
  assume_role_policy   = data.aws_iam_policy_document.assume.json
  tags                 = var.tags
}

# Keep execution permissions project-scoped rather than attaching the AWS-managed
# policy, which grants pull/log access across all repositories and log groups.
resource "aws_iam_role_policy" "execution" {
  #checkov:skip=CKV_AWS_111:ecr:GetAuthorizationToken and guardduty:SendSecurityTelemetry do not support resource-level permissions; all other actions are exact-resource scoped.
  #checkov:skip=CKV_AWS_356:Only AWS APIs that require Resource "*" use it; private-image, log, secret, and KMS actions use declared ARNs.
  name = "${var.name}-execution"
  role = aws_iam_role.execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AuthenticateToECR"
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken"]
        Resource = "*"
      },
      {
        Sid    = "PullApplicationImages"
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:BatchGetImage",
          "ecr:GetDownloadUrlForLayer",
        ]
        Resource = var.ecr_repository_arns
      },
      {
        Sid    = "PullGuardDutyAgentImage"
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:BatchGetImage",
          "ecr:GetDownloadUrlForLayer",
        ]
        Resource = local.guardduty_agent_repository_arn
      },
      {
        Sid      = "SendGuardDutyRuntimeTelemetry"
        Effect   = "Allow"
        Action   = ["guardduty:SendSecurityTelemetry"]
        Resource = "*"
      },
      {
        Sid    = "WriteServiceLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:${aws_cloudwatch_log_group.this.name}:log-stream:*"
      },
      {
        Sid      = "ReadDeclaredSecrets"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = local.secret_arns
      },
      {
        Sid      = "DecryptRuntimeValues"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = var.kms_key_arn
      },
    ]
  })
}

# Creates an IAM role with a narrowly defined trust relationship.
resource "aws_iam_role" "task" {
  permissions_boundary = var.permissions_boundary_arn
  name                 = "${var.name}-task"
  assume_role_policy   = data.aws_iam_policy_document.assume.json
  tags                 = var.tags
}

resource "aws_iam_role_policy" "task" {
  #checkov:skip=CKV_AWS_111:ssmmessages channel APIs and X-Ray ingestion APIs do not support resource-level permissions; all restrictable actions are ARN-scoped.
  #checkov:skip=CKV_AWS_356:Only AWS APIs that formally require Resource "*" use it; every restrictable application permission has an exact ARN.
  role = aws_iam_role.task.id

  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = local.application_statements
  })
}

# Stores application, task, or ECS Exec logs with controlled retention.
resource "aws_cloudwatch_log_group" "this" {
  name              = "/aws/ecs/${var.name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
  tags              = var.tags
}

# Defines immutable container, role, logging, health, and resource settings for a workload revision.
resource "aws_ecs_task_definition" "this" {
  family                   = var.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = tostring(var.cpu)
  memory                   = tostring(var.memory)
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn
  container_definitions    = jsonencode(local.container_definitions)

  volume {
    name = "tmp"
  }

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  tags = var.tags
}

# Keeps the requested number of application tasks running and connected to networking and load balancing.
resource "aws_ecs_service" "this" {
  name                               = var.name
  cluster                            = var.cluster_arn
  task_definition                    = aws_ecs_task_definition.this.arn
  desired_count                      = var.desired_count
  launch_type                        = "FARGATE"
  enable_execute_command             = true
  enable_ecs_managed_tags            = true
  propagate_tags                     = "SERVICE"
  wait_for_steady_state              = true
  deployment_minimum_healthy_percent = var.desired_count == 0 ? 0 : 100
  deployment_maximum_percent         = 200
  health_check_grace_period_seconds  = var.target_group_arn == null ? null : 60

  # Places ECS tasks in selected subnets and security groups without public addresses.
  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = var.security_group_ids
    assign_public_ip = false
  }

  # Generates repeated nested configuration from the supplied collection.
  dynamic "load_balancer" {
    for_each = var.target_group_arn == null ? [] : [1]

    # Defines the nested block emitted for each item in the dynamic collection.
    content {
      target_group_arn = var.target_group_arn
      container_name   = var.name
      container_port   = var.container_port
    }
  }

  # Stop unhealthy deployments. Rollback is enabled by deployment orchestration
  # only after ECS has a COMPLETED deployment that can be restored.
  deployment_circuit_breaker {
    enable   = true
    rollback = var.rollback_enabled
  }

  depends_on = [
    aws_iam_role_policy.execution,
    aws_iam_role_policy.task,
  ]

  tags = var.tags
}

# Registers the ECS service as a scalable target with capacity limits.
resource "aws_appautoscaling_target" "this" {
  count              = var.enable_autoscaling && var.desired_count > 0 ? 1 : 0
  max_capacity       = coalesce(var.autoscaling_max_capacity, max(var.desired_count * 4, 2))
  min_capacity       = max(var.desired_count, 1)
  resource_id        = "service/${element(reverse(split("/", var.cluster_arn)), 0)}/${aws_ecs_service.this.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

# Adjusts ECS task count in response to measured utilization.
resource "aws_appautoscaling_policy" "cpu" {
  count              = var.enable_autoscaling && var.desired_count > 0 ? 1 : 0
  name               = "${var.name}-cpu"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.this[0].resource_id
  scalable_dimension = aws_appautoscaling_target.this[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.this[0].service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }

    target_value = var.autoscaling_cpu_target
  }
}

# Memory target tracking complements CPU scaling for workloads that can
# exhaust memory before CPU reaches the configured threshold.
resource "aws_appautoscaling_policy" "memory" {
  count              = var.enable_autoscaling && var.desired_count > 0 ? 1 : 0
  name               = "${var.name}-memory"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.this[0].resource_id
  scalable_dimension = aws_appautoscaling_target.this[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.this[0].service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageMemoryUtilization"
    }

    target_value = var.autoscaling_memory_target
  }
}
