# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Publishes reusable values produced by the ecs service Terraform module.

# Output `service_name`: Name of the ECS service used by deployment, autoscaling, and monitoring commands.
output "service_name" {
  value = aws_ecs_service.this.name
}
# Output `service_arn`: ARN of the service resource consumed by this module.
output "service_arn" {
  value = aws_ecs_service.this.id
}
# Output `task_role_arn`: ARN of the task role resource consumed by this module.
output "task_role_arn" {
  value = aws_iam_role.task.arn
}
# Output `task_definition_arn`: ARN of the task definition resource consumed by this module.
output "task_definition_arn" {
  value = aws_ecs_task_definition.this.arn
}
