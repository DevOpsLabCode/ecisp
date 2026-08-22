# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Publishes reusable values produced by the alb Terraform module.

# Output `arn`: ARN of the Application Load Balancer for IAM, monitoring, and cross-module references.
output "arn" {
  value = aws_lb.this.arn
}
# Output `dns_name`: AWS-generated ALB hostname -- Golem's application URL when no custom domain is configured.
output "dns_name" {
  value = aws_lb.this.dns_name
}
# Output `zone_id`: AWS hosted-zone identifier required by a Route 53 alias target, if one is ever added.
output "zone_id" {
  value = aws_lb.this.zone_id
}
# Output `target_group_arn`: ALB target-group ARN used to register the golem-backend ECS service.
output "target_group_arn" {
  value = aws_lb_target_group.backend.arn
}

output "target_group_arn_suffix" {
  description = "Target-group ARN suffix used by CloudWatch dimensions."
  value       = aws_lb_target_group.backend.arn_suffix
}
