# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Publishes backup identifiers for audit, restore automation, and monitoring.

output "vault_name" {
  description = "AWS Backup vault name."
  value       = aws_backup_vault.this.name
}

output "vault_arn" {
  description = "AWS Backup vault ARN."
  value       = aws_backup_vault.this.arn
}

output "plan_id" {
  description = "AWS Backup plan ID."
  value       = aws_backup_plan.this.id
}

output "vault_lock_enabled" {
  description = "Whether Compliance-mode Vault Lock is configured."
  value       = var.enable_vault_lock
}
