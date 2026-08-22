# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Publishes identifiers consumed by environment and CI configuration.

output "github_oidc_provider_arn" {
  description = "ARN of the account-wide GitHub Actions OIDC provider."
  value       = aws_iam_openid_connect_provider.github.arn
}

output "guardduty_detector_id" {
  description = "ID of the regional GuardDuty detector."
  value       = aws_guardduty_detector.this.id
}

output "guardduty_runtime_monitoring_enabled" {
  description = "Whether GuardDuty Runtime Monitoring with Fargate agent management is enabled."
  value       = var.enable_guardduty_runtime_monitoring
}

output "enhanced_ecr_scanning_enabled" {
  description = "Whether account-wide enhanced ECR continuous scanning is enabled."
  value       = var.enable_enhanced_ecr_scanning
}

output "terraform_plan_role_arn" {
  description = "Read-only GitHub OIDC role ARN for trusted post-merge plans using protected GitHub environments."
  value       = aws_iam_role.terraform_plan.arn
}

output "terraform_apply_role_arn" {
  description = "Protected GitHub OIDC role ARN for manual Terraform applies."
  value       = aws_iam_role.terraform_apply.arn
}

output "terraform_permissions_boundary_arn" {
  description = "AWS-managed permissions boundary that every environment-created IAM role must retain."
  value       = local.permissions_boundary_arn
}
