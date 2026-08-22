# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Environment: dev
# Purpose: Supplies a genuinely minimal, cheap-to-run configuration for the Terraform root stack.

environment        = "dev"
aws_region         = "us-east-1"
vpc_cidr           = "10.30.0.0/16"
az_count           = 2
nat_gateway_per_az = false

# REPLACED_BY_CI: a real deploy pipeline pushes an image to the ECR repositories this
# stack creates (module.ecr) and overrides these with an explicit tag or sha256 digest.
# Terraform itself never builds or pushes images.
backend_image       = "REPLACED_BY_CI"
iam_responder_image = "REPLACED_BY_CI"

backend_cpu                    = 256
backend_memory                 = 512
backend_desired_count          = 1
backend_rollback_enabled       = false
iam_responder_cpu              = 256
iam_responder_memory           = 512
iam_responder_desired_count    = 1
iam_responder_rollback_enabled = false
allow_zero_capacity            = true

db_instance_class    = "db.t4g.micro"
db_allocated_storage = 20
db_multi_az          = false

deletion_protection = false

cloudtrail_retention_days = 90

# No custom domain or ACM certificate for a dev trial -- the ALB serves plain HTTP
# on its own AWS-generated hostname (see modules/alb's README and terraform/README.md's
# ALB/certificate decision). Set both when testing beyond a quick trial.
domain_name     = ""
certificate_arn = null

alarm_email = ""
tags = {
  Owner      = "DevOpsLabCode"
  CostCenter = "GolemDefender"
}

# Development backups remain deletable and avoid cold-storage minimums. Vault Lock is
# irreversible once locked (see modules/backup's README) -- never enable it for a
# disposable dev environment.
enable_backup_vault_lock          = false
backup_retention_days             = 14
backup_max_retention_days         = 120
backup_cold_storage_after_days    = null
backup_vault_lock_changeable_days = 3
