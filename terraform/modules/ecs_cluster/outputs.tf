# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Publishes reusable values produced by the ecs cluster Terraform module.

# Output `cluster_arn`: ARN of the ECS cluster that will run this service.
output "cluster_arn" {
  value = aws_ecs_cluster.this.arn
}
# Output `cluster_name`: Name of the ECS cluster used to construct service and autoscaling identifiers.
output "cluster_name" {
  value = aws_ecs_cluster.this.name
}
