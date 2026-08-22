# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Composes reusable AWS modules into the complete, self-sufficient Golem Defender environment.
# Reading guide: Each comment explains why the following Terraform block exists. See terraform/README.md for the
# full module inventory, the three explicit decisions this composition embodies (ALB/certificate, global/account
# scope, Vault Lock default), and the honest statement of what remains unverified without real AWS credentials.

locals {
  name = "${var.project_name}-${var.environment}"
  tags = merge(var.tags, {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "Terraform"
    Owner       = "DevOps Lab Inc."
    Repository  = "${var.github_org}/${var.github_repo}"
  })
  permissions_boundary_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/PowerUserAccess"

  # No Route 53/ACM automation in V1 (see terraform/README.md) -- domain_name is purely informational, set by an
  # operator who has already pointed real DNS at the ALB and obtained a matching certificate_arn out of band.
  application_url = var.domain_name != "" ? "https://${var.domain_name}" : "http://${module.alb.dns_name}"

  # golem-iam-responder authenticates to golem-backend, and golem-backend authenticates the request, with the same
  # fleet-wide bearer credential -- see iam-responder/app/backend_client.py and
  # ui/backend/app/main.py's _authenticated_iam_component.
  iam_responder_api_key_secret = "${module.secrets_manager.secret_arn}:IAM_RESPONDER_API_KEY::"
}

# Validates an invariant early so an unsafe or inconsistent plan cannot proceed.
check "production_safety" {
  assert {
    condition     = var.allow_zero_capacity || var.environment != "prod" || (var.deletion_protection && var.db_multi_az && var.backend_desired_count >= 2)
    error_message = "Production requires deletion protection, Multi-AZ RDS, and at least two golem-backend tasks."
  }
}

# Invokes the reusable kms module and passes this environment configuration into it.
module "kms" {
  source = "./modules/kms"
  name   = local.name
  tags   = local.tags
}

# Central terminal log sink for ALB and CloudTrail S3 server-access records.
module "access_logs" {
  source        = "./modules/access_logs"
  name          = "${local.name}-${data.aws_caller_identity.current.account_id}-access-logs"
  force_destroy = var.environment == "dev"
  tags          = local.tags
}

# Invokes the reusable networking module and passes this environment configuration into it.
module "networking" {
  source                   = "./modules/networking"
  name                     = local.name
  cidr                     = var.vpc_cidr
  az_count                 = var.az_count
  nat_gateway_per_az       = var.nat_gateway_per_az
  kms_key_arn              = module.kms.key_arn
  permissions_boundary_arn = local.permissions_boundary_arn
  tags                     = local.tags
}

# Invokes the Golem-custom security module (plain internet ingress, no CloudFront prefix list; no redis SG) and
# passes this environment configuration into it.
module "security" {
  source   = "./modules/security"
  name     = local.name
  vpc_id   = module.networking.vpc_id
  vpc_cidr = var.vpc_cidr
  tags     = local.tags
}

# Invokes the reusable ecr module. Golem needs exactly two repositories.
module "ecr" {
  source       = "./modules/ecr"
  name         = local.name
  repositories = ["backend", "iam-responder"]
  kms_key_arn  = module.kms.key_arn
  force_delete = var.environment == "dev"
  tags         = local.tags
}

# Fleet-wide IAM_RESPONDER_API_KEY, shared between golem-backend and golem-iam-responder.
module "secrets_manager" {
  source                  = "./modules/secrets_manager"
  name                    = local.name
  kms_key_arn             = module.kms.key_arn
  recovery_window_in_days = var.environment == "prod" ? 30 : 7
  tags                    = local.tags
}

# Invokes the reusable database module and passes this environment configuration into it.
module "database" {
  source                      = "./modules/rds_postgres"
  name                        = local.name
  subnet_ids                  = module.networking.db_subnet_ids
  security_group_ids          = [module.security.db_sg_id]
  kms_key_arn                 = module.kms.key_arn
  instance_class              = var.db_instance_class
  allocated_storage           = var.db_allocated_storage
  multi_az                    = var.db_multi_az
  deletion_protection         = var.deletion_protection
  secret_recovery_window_days = var.environment == "prod" ? 30 : 7
  permissions_boundary_arn    = local.permissions_boundary_arn
  tags                        = local.tags
}

# Invokes the reusable cluster module and passes this environment configuration into it.
module "cluster" {
  source      = "./modules/ecs_cluster"
  name        = local.name
  kms_key_arn = module.kms.key_arn
  tags        = local.tags
}

# Invokes the Golem-custom alb module (no CloudFront-gated no-certificate branch) and passes this environment
# configuration into it.
module "alb" {
  source               = "./modules/alb"
  name                 = local.name
  vpc_id               = module.networking.vpc_id
  subnet_ids           = module.networking.public_subnet_ids
  security_group_ids   = [module.security.alb_sg_id]
  certificate_arn      = var.certificate_arn
  deletion_protection  = var.deletion_protection
  access_log_bucket_id = module.access_logs.bucket_id
  access_log_prefix    = "alb"
  tags                 = local.tags

  # A targeted deploy otherwise depends only on selected output values. Wait for
  # complete networking and access-log modules so the Internet Gateway, public
  # routing, and S3 delivery policy all exist before AWS creates the
  # internet-facing ALB and enables access logging.
  depends_on = [
    module.networking,
    module.access_logs,
  ]
}

# Invokes the reusable golem_iam_responder_execution module -- the execution-side half of Tier 4's cross-account IAM
# revocation trust (see modules/golem_iam_responder_execution/README.md). The other half,
# golem_monitored_account_trust, is applied separately by each monitored account's own operators, never by this
# root stack.
module "golem_iam_responder_execution" {
  source = "./modules/golem_iam_responder_execution"
  tags   = local.tags
}

# Invokes the reusable backend module. Exposed via the ALB target group; the only service reachable from outside
# the VPC. Env var names (BACKEND_URL, IAM_RESPONDER_API_KEY, DATABASE_URL) and the health-check path
# (/api/health, wired through modules/alb's default) are read directly from ui/backend/app/main.py and
# ui/backend/app/db.py, not guessed.
module "backend" {
  source                    = "./modules/ecs_service"
  name                      = "${local.name}-backend"
  cluster_arn               = module.cluster.cluster_arn
  subnet_ids                = module.networking.app_subnet_ids
  security_group_ids        = [module.security.app_sg_id]
  image                     = var.backend_image
  ecr_repository_arns       = module.ecr.repository_arns
  cpu                       = var.backend_cpu
  memory                    = var.backend_memory
  desired_count             = var.backend_desired_count
  rollback_enabled          = var.backend_rollback_enabled
  target_group_arn          = module.alb.target_group_arn
  kms_key_arn               = module.kms.key_arn
  queue_arn                 = ""
  queue_actions             = []
  object_storage_bucket_arn = null
  ses_identity_arn          = null
  enable_xray               = false
  environment = {
    BACKEND_URL = local.application_url
  }
  secrets = {
    DATABASE_URL          = "${module.database.runtime_secret_arn}:DATABASE_URL::"
    IAM_RESPONDER_API_KEY = local.iam_responder_api_key_secret
  }
  permissions_boundary_arn = local.permissions_boundary_arn
  tags                     = local.tags
}

# Invokes the reusable golem-iam-responder module -- the standalone Tier 4 AWS component (see
# ../iam-responder/README.md). Never exposed via the ALB: it is a polling loop with no HTTP server at all (see
# iam-responder/app/__main__.py), so expose_port/enable_health_check/target_group_arn are all off/null.
module "iam_responder" {
  source                    = "./modules/ecs_service"
  name                      = "${local.name}-iam-responder"
  cluster_arn               = module.cluster.cluster_arn
  subnet_ids                = module.networking.app_subnet_ids
  security_group_ids        = [module.security.app_sg_id]
  image                     = var.iam_responder_image
  ecr_repository_arns       = module.ecr.repository_arns
  cpu                       = var.iam_responder_cpu
  memory                    = var.iam_responder_memory
  desired_count             = var.iam_responder_desired_count
  rollback_enabled          = var.iam_responder_rollback_enabled
  expose_port               = false
  enable_health_check       = false
  target_group_arn          = null
  kms_key_arn               = module.kms.key_arn
  queue_arn                 = ""
  queue_actions             = []
  object_storage_bucket_arn = null
  ses_identity_arn          = null
  enable_xray               = false
  environment = {
    BACKEND_URL = local.application_url
    LOG_LEVEL   = "INFO"
  }
  secrets = {
    IAM_RESPONDER_API_KEY = local.iam_responder_api_key_secret
  }
  permissions_boundary_arn = local.permissions_boundary_arn
  tags                     = local.tags
}

# Grants golem-iam-responder's own task role permission to assume into every monitored account's trust role. This
# is deliberately a separate attachment, not a module input: modules/ecs_service knows nothing about cross-account
# trust policies, and golem_iam_responder_execution knows nothing about ECS -- see both modules' READMEs for why
# this privilege separation is load-bearing, not incidental.
resource "aws_iam_role_policy_attachment" "iam_responder_assume_monitored_accounts" {
  # modules/ecs_service's task role never sets an IAM path, so its ARN is always
  # exactly arn:...:role/<name> -- one "/" splits it into exactly two parts.
  role       = split("/", module.iam_responder.task_role_arn)[1]
  policy_arn = module.golem_iam_responder_execution.policy_arn
}

# Invokes the Golem-simplified cloudwatch module (no redis/sqs/cloudfront) and passes this environment
# configuration into it.
module "cloudwatch" {
  source                  = "./modules/cloudwatch"
  name                    = local.name
  alb_arn_suffix          = split("loadbalancer/", module.alb.arn)[1]
  target_group_arn_suffix = module.alb.target_group_arn_suffix
  cluster_name            = module.cluster.cluster_name
  service_names = {
    backend       = module.backend.service_name
    iam_responder = module.iam_responder.service_name
  }
  db_identifier    = module.database.db_identifier
  sns_email        = var.alarm_email
  kms_key_arn      = module.kms.key_arn
  account_root_arn = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
  tags             = local.tags
}

# Invokes the reusable backup module and passes this environment configuration into it.
module "backup" {
  source                         = "./modules/backup"
  name                           = local.name
  kms_key_arn                    = module.kms.key_arn
  resource_arns                  = [module.database.db_arn]
  enable_vault_lock              = var.enable_backup_vault_lock
  minimum_retention_days         = var.backup_retention_days
  maximum_retention_days         = var.backup_max_retention_days
  cold_storage_after_days        = var.backup_cold_storage_after_days
  vault_lock_changeable_for_days = var.backup_vault_lock_changeable_days
  permissions_boundary_arn       = local.permissions_boundary_arn
  tags                           = local.tags
}

# Invokes the reusable cloudtrail module and passes this environment configuration into it.
module "cloudtrail" {
  source                   = "./modules/cloudtrail"
  name                     = local.name
  kms_key_arn              = module.kms.key_arn
  retention_days           = var.cloudtrail_retention_days
  access_log_bucket_id     = module.access_logs.bucket_id
  enable_insights          = var.environment == "prod"
  permissions_boundary_arn = local.permissions_boundary_arn
  tags                     = local.tags
}
