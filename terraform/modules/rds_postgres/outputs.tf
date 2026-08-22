# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Publishes database endpoints, identifiers, and protected secret references.

output "endpoint" {
  description = "Direct RDS PostgreSQL writer endpoint, excluding the port."
  value       = aws_db_instance.this.address
}

output "proxy_endpoint" {
  description = "RDS Proxy endpoint used by ECS tasks to pool and protect PostgreSQL connections."
  value       = aws_db_proxy.this.endpoint
}

output "secret_arn" {
  description = "Secrets Manager ARN containing the database login used by RDS Proxy."
  value       = aws_secretsmanager_secret.db.arn
  sensitive   = true

  # Consumers must not receive the secret ARN until an AWSCURRENT database
  # credential version exists.
  depends_on = [
    aws_secretsmanager_secret_version.db,
  ]
}

output "db_arn" {
  description = "RDS database instance ARN used by AWS Backup."
  value       = aws_db_instance.this.arn
}

output "db_identifier" {
  description = "RDS identifier used by CloudWatch alarm dimensions."
  value       = aws_db_instance.this.identifier
}

output "runtime_secret_arn" {
  description = "Secrets Manager ARN containing DATABASE_URL, wired directly into golem-backend's ECS task definition secrets map."
  value       = aws_secretsmanager_secret.runtime.arn
  sensitive   = true

  # Force Terraform to create the JSON secret value and AWSCURRENT stage
  # before exposing the ARN to ECS.
  depends_on = [
    aws_secretsmanager_secret_version.runtime,
  ]
}
