# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Publishes deployment identifiers, endpoints, secret ARNs, and role ARNs from the root stack.
# Reading guide: Each comment explains why the following Terraform block exists.

# Output `application_url`: Canonical HTTPS or HTTP application URL, depending on whether domain_name is configured.
output "application_url" {
  value = local.application_url
}

# Output `alb_dns_name`: AWS-generated ALB hostname.
output "alb_dns_name" {
  value = module.alb.dns_name
}

# Output `ecr_repository_urls`: Map of image names to ECR URLs used by CI image builds.
output "ecr_repository_urls" {
  value = module.ecr.repository_urls
}

# Output `database_secret_arn`: ARN of the database-credential secret consumed by RDS Proxy's own auth.
output "database_secret_arn" {
  value     = module.database.secret_arn
  sensitive = true
}

# Output `database_runtime_secret_arn`: ARN of the secret containing DATABASE_URL.
output "database_runtime_secret_arn" {
  value     = module.database.runtime_secret_arn
  sensitive = true
}

# Output `golem_secrets_arn`: ARN of the secret containing IAM_RESPONDER_API_KEY.
output "golem_secrets_arn" {
  value     = module.secrets_manager.secret_arn
  sensitive = true
}

# Output `ecs_cluster_arn`: ARN of the shared ECS cluster.
output "ecs_cluster_arn" {
  value = module.cluster.cluster_arn
}

# Output `backend_service_name`: ECS golem-backend service name, used by deployment scripts to scale and inspect the workload.
output "backend_service_name" {
  value = module.backend.service_name
}

# Output `backend_task_definition_arn`: ARN of the golem-backend task definition.
output "backend_task_definition_arn" {
  value = module.backend.task_definition_arn
}

# Output `iam_responder_service_name`: ECS golem-iam-responder service name.
output "iam_responder_service_name" {
  value = module.iam_responder.service_name
}

# Output `iam_responder_task_definition_arn`: ARN of the golem-iam-responder task definition.
output "iam_responder_task_definition_arn" {
  value = module.iam_responder.task_definition_arn
}

# Output `iam_responder_task_role_arn`: ARN of golem-iam-responder's own task role -- the execution identity granted
# sts:AssumeRole into every monitored account's trust role (see golem_monitored_account_trust's own README for the
# other, separately applied, half of this trust relationship).
output "iam_responder_task_role_arn" {
  value = module.iam_responder.task_role_arn
}

# Output `app_subnet_ids`: Private application subnet IDs used by both ECS services.
output "app_subnet_ids" {
  value = module.networking.app_subnet_ids
}

# Output `app_security_group_id`: Security group attached to both ECS services.
output "app_security_group_id" {
  value = module.security.app_sg_id
}

# Output `backup_vault_lock_enabled`: Whether Compliance-mode Vault Lock is active for this environment.
output "backup_vault_lock_enabled" {
  value = module.backup.vault_lock_enabled
}

# Output `cloudtrail_arn`: ARN of the multi-region CloudTrail trail.
output "cloudtrail_arn" {
  value = module.cloudtrail.trail_arn
}
