# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Declares the complete Fargate service contract for networking, sizing, IAM, secrets, health, scaling, logging, and tracing.

variable "name" {
  type        = string
  description = "Stable ECS service, task family, role, and log-group name prefix."

  validation {
    condition     = can(regex("^[A-Za-z0-9_-]{3,64}$", var.name))
    error_message = "name must contain 3-64 ECS-compatible characters."
  }
}

variable "cluster_arn" {
  type        = string
  description = "ARN of the ECS cluster that runs the service."

  validation {
    condition     = can(regex(":ecs:[^:]+:[0-9]{12}:cluster/", var.cluster_arn))
    error_message = "cluster_arn must be an ECS cluster ARN."
  }
}

variable "subnet_ids" {
  type        = list(string)
  description = "Private application subnet IDs used by Fargate ENIs."

  validation {
    condition     = length(var.subnet_ids) >= 2 && alltrue([for id in var.subnet_ids : can(regex("^subnet-[0-9a-f]+$", id))])
    error_message = "subnet_ids must contain at least two valid subnet IDs."
  }
}

variable "security_group_ids" {
  type        = list(string)
  description = "Security groups attached to Fargate ENIs."

  validation {
    condition     = length(var.security_group_ids) > 0 && alltrue([for id in var.security_group_ids : can(regex("^sg-[0-9a-f]+$", id))])
    error_message = "security_group_ids must contain at least one valid security-group ID."
  }
}

variable "ecr_repository_arns" {
  type        = list(string)
  description = "Exact ECR repository ARNs from which the task execution role may pull application images."

  validation {
    condition     = length(var.ecr_repository_arns) > 0 && alltrue([for arn in var.ecr_repository_arns : can(regex("^arn:[^:]+:ecr:[^:]+:[0-9]{12}:repository/", arn))])
    error_message = "ecr_repository_arns must contain at least one valid ECR repository ARN."
  }
}

variable "image" {
  type        = string
  description = "Container image URI with an explicit tag or digest."

  validation {
    condition     = trimspace(var.image) != "" && (can(regex("@sha256:[0-9a-f]{64}$", var.image)) || can(regex(":([A-Za-z0-9_.-]+)$", var.image)))
    error_message = "image must be non-empty and include an explicit tag or sha256 digest."
  }
}

variable "container_port" {
  type        = number
  description = "TCP port on which the application container listens."
  default     = 8000

  validation {
    condition     = floor(var.container_port) == var.container_port && var.container_port >= 1 && var.container_port <= 65535
    error_message = "container_port must be a valid whole-number TCP port."
  }
}

variable "expose_port" {
  type        = bool
  description = "Register an application port and optional load-balancer mapping."
  default     = true
}

variable "cpu" {
  type        = number
  description = "Fargate task CPU units."

  validation {
    condition     = contains([256, 512, 1024, 2048, 4096, 8192, 16384], var.cpu)
    error_message = "cpu must be a supported Fargate CPU value."
  }
}

variable "memory" {
  type        = number
  description = "Fargate task memory in MiB."

  validation {
    condition     = floor(var.memory) == var.memory && var.memory >= 512
    error_message = "memory must be a whole number of at least 512 MiB."
  }
}

variable "desired_count" {
  type        = number
  description = "Steady-state service task count."

  validation {
    condition     = floor(var.desired_count) == var.desired_count && var.desired_count >= 0
    error_message = "desired_count must be a non-negative whole number."
  }
}

variable "rollback_enabled" {
  type        = bool
  description = "Roll back a failed deployment only when orchestration has verified that a COMPLETED ECS deployment exists."
  default     = false
}

variable "target_group_arn" {
  type        = string
  description = "Optional ALB target-group ARN used by an exposed service."
  default     = null
  nullable    = true
}

variable "command" {
  type        = list(string)
  description = "Optional container command override."
  default     = []
}

variable "environment" {
  type        = map(string)
  description = "Non-sensitive container environment variables."
  default     = {}
}

variable "secrets" {
  type        = map(string)
  description = "Container environment names mapped to Secrets Manager value references."
  default     = {}
}

variable "kms_key_arn" {
  type        = string
  description = "Customer-managed KMS key ARN used by logs, secrets, queues, and object storage."
}

variable "queue_arn" {
  type        = string
  description = "SQS queue ARN the application can consume and publish. Golem's services have no SQS integration in V1; pass an empty string and leave queue_actions empty (the default statements it would otherwise produce are gated by queue_actions, not by this value alone)."
}


variable "queue_actions" {
  type        = set(string)
  description = "Exact SQS data-plane actions granted to this workload; use an empty set for services with no queue integration."
  default = [
    "sqs:DeleteMessage",
    "sqs:GetQueueAttributes",
    "sqs:ReceiveMessage",
    "sqs:SendMessage",
  ]

  validation {
    condition = length(setsubtract(var.queue_actions, toset([
      "sqs:ChangeMessageVisibility",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
      "sqs:GetQueueUrl",
      "sqs:ReceiveMessage",
      "sqs:SendMessage",
    ]))) == 0
    error_message = "queue_actions contains an action outside the approved SQS data-plane allowlist."
  }
}

variable "object_storage_bucket_arn" {
  type        = string
  description = "Optional private S3 bucket ARN used for application objects."
  default     = null
  nullable    = true
}

variable "enable_health_check" {
  type        = bool
  description = "Add the application-container health check."
  default     = true
}

variable "enable_autoscaling" {
  type        = bool
  description = "Create Application Auto Scaling target and CPU/memory policies."
  default     = true
}

variable "autoscaling_max_capacity" {
  type        = number
  description = "Optional explicit autoscaling maximum; null uses four times desired count with a floor of two."
  default     = null
  nullable    = true

  validation {
    condition     = var.autoscaling_max_capacity == null || (floor(var.autoscaling_max_capacity) == var.autoscaling_max_capacity && var.autoscaling_max_capacity >= 1)
    error_message = "autoscaling_max_capacity must be null or a positive whole number."
  }
}

variable "autoscaling_cpu_target" {
  type        = number
  description = "Average ECS CPU percentage targeted by autoscaling."
  default     = 60

  validation {
    condition     = var.autoscaling_cpu_target >= 10 && var.autoscaling_cpu_target <= 90
    error_message = "autoscaling_cpu_target must be between 10 and 90."
  }
}


variable "autoscaling_memory_target" {
  type        = number
  description = "Average ECS memory percentage targeted by the optional memory autoscaling policy."
  default     = 70

  validation {
    condition     = var.autoscaling_memory_target >= 10 && var.autoscaling_memory_target <= 90
    error_message = "autoscaling_memory_target must be between 10 and 90."
  }
}

variable "log_retention_days" {
  type        = number
  description = "CloudWatch application-log retention; one year is the security baseline."
  default     = 365

  validation {
    condition     = var.log_retention_days >= 365
    error_message = "Application logs must be retained for at least 365 days."
  }
}

variable "ses_identity_arn" {
  type        = string
  description = "Optional verified SES identity that tasks may use for outbound mail."
  default     = null
  nullable    = true
}

variable "enable_xray" {
  type        = bool
  description = "Run the AWS X-Ray daemon sidecar and grant trace write permissions."
  default     = true
}

variable "xray_image" {
  type        = string
  description = "Pinned AWS X-Ray daemon container image. The daemon is in maintenance mode; migrate to ADOT/OpenTelemetry before end of support."
  default     = "public.ecr.aws/xray/aws-xray-daemon:3.6.6"

  validation {
    condition     = can(regex("^public\\.ecr\\.aws/xray/aws-xray-daemon:[0-9]+\\.[0-9]+\\.[0-9]+$", var.xray_image))
    error_message = "xray_image must use an explicit numeric version tag rather than a mutable major tag."
  }
}

variable "permissions_boundary_arn" {
  type        = string
  description = "AWS-managed PowerUserAccess policy ARN used as the permissions boundary for every workload IAM role."

  validation {
    condition     = can(regex("^arn:[^:]+:iam::aws:policy/PowerUserAccess$", var.permissions_boundary_arn))
    error_message = "permissions_boundary_arn must be the partition-correct AWS-managed PowerUserAccess policy ARN."
  }
}

variable "tags" {
  type        = map(string)
  description = "Common ownership, environment, cost, and governance tags."
  default     = {}
}

check "fargate_size" {
  assert {
    condition = contains(
      lookup({
        "256"   = [512, 1024, 2048]
        "512"   = [1024, 2048, 3072, 4096]
        "1024"  = range(2048, 8193, 1024)
        "2048"  = range(4096, 16385, 1024)
        "4096"  = range(8192, 30721, 1024)
        "8192"  = range(16384, 61441, 4096)
        "16384" = range(32768, 122881, 8192)
      }, tostring(var.cpu), []),
      var.memory,
    )
    error_message = "memory is not a supported Fargate value for the selected cpu."
  }
}

check "load_balancer_contract" {
  assert {
    condition     = (var.target_group_arn == null) || var.expose_port
    error_message = "target_group_arn requires expose_port=true."
  }
}

check "autoscaling_contract" {
  assert {
    condition     = var.autoscaling_max_capacity == null || var.autoscaling_max_capacity >= max(var.desired_count, 1)
    error_message = "autoscaling_max_capacity cannot be below the service minimum capacity."
  }
}
