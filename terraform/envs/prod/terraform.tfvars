# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Environment: prod
# Purpose: Supplies documented production environment values for the Terraform root stack.
# This file is provided for structural completeness (mirroring demand-gig-engine's envs/{dev,prod} layout) and has
# NOT been applied to any real AWS account -- review every value, especially certificate_arn/domain_name and the
# backup Vault Lock setting, before ever running `terraform apply` against it. See terraform/README.md.

environment        = "prod"
aws_region         = "us-east-1"
vpc_cidr           = "10.31.0.0/16"
az_count           = 3
nat_gateway_per_az = true

# REPLACED_BY_CI: see envs/dev/terraform.tfvars's own comment.
backend_image       = "REPLACED_BY_CI"
iam_responder_image = "REPLACED_BY_CI"

backend_cpu                    = 1024
backend_memory                 = 2048
backend_desired_count          = 2
backend_rollback_enabled       = true
iam_responder_cpu              = 512
iam_responder_memory           = 1024
iam_responder_desired_count    = 1
iam_responder_rollback_enabled = true
allow_zero_capacity            = false

db_instance_class    = "db.r6g.large"
db_allocated_storage = 100
db_multi_az          = true

deletion_protection = true

cloudtrail_retention_days = 365

# A real deployment beyond a trial needs its own domain and a regional ACM certificate
# issued and DNS-validated outside this stack (Route 53 automation is out of scope --
# see terraform/README.md). Point real DNS at the output alb_dns_name, then set both
# of these before applying to production.
domain_name     = ""
certificate_arn = null

alarm_email = ""
tags = {
  Owner      = "DevOpsLabCode"
  CostCenter = "GolemDefender"
}

# Compliance-mode Vault Lock is irreversible once its grace period elapses (see
# modules/backup's README) -- left false here deliberately; enable it only after an
# operator has validated retention requirements for this specific account.
enable_backup_vault_lock          = false
backup_retention_days             = 90
backup_max_retention_days         = 2555
backup_cold_storage_after_days    = null
backup_vault_lock_changeable_days = 7
