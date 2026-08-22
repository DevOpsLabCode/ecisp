# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Provisions resilient encrypted PostgreSQL, enforced TLS, enhanced monitoring, protected credentials, and RDS Proxy.
# Adapted from demand-gig-engine/terraform/modules/rds_postgres -- architecture is unchanged (RDS instance + RDS Proxy +
# two Secrets Manager secrets). Golem's copy renames the hardcoded database/username literals to Golem's own and drops
# the Django SECRET_KEY from the runtime secret: golem-backend (ui/backend/app/db.py) is a FastAPI/SQLAlchemy service
# with no equivalent concept, and only reads DATABASE_URL (see terraform/README.md).

data "aws_iam_policy_document" "monitoring_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["monitoring.rds.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "monitoring" {
  permissions_boundary = var.permissions_boundary_arn
  name                 = "${var.name}-rds-monitoring"
  assume_role_policy   = data.aws_iam_policy_document.monitoring_assume.json
  tags                 = var.tags
}

resource "aws_iam_role_policy_attachment" "monitoring" {
  role       = aws_iam_role.monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

resource "random_password" "db" {
  length  = 32
  special = false
}

# A stable random suffix prevents final-snapshot name collisions when a protected
# database is intentionally destroyed and later recreated with the same identifier.
resource "random_id" "final_snapshot" {
  byte_length = 4

  keepers = {
    identifier = var.name
  }
}

resource "aws_secretsmanager_secret" "db" {
  #checkov:skip=CKV2_AWS_57:Database credential rotation is an atomic RDS Proxy runbook that updates PostgreSQL and Secrets Manager together to avoid credential desynchronization.
  name                    = "${var.name}/database"
  kms_key_id              = var.kms_key_arn
  recovery_window_in_days = var.secret_recovery_window_days
  tags                    = var.tags
}

resource "aws_secretsmanager_secret_version" "db" {
  secret_id     = aws_secretsmanager_secret.db.id
  secret_string = jsonencode({ username = local.db_username, password = random_password.db.result })
}

locals {
  # Matches ui/docker-compose.yml's DATABASE_URL convention exactly (username
  # "golem", database "golem_defender") so a developer moving between local
  # Docker Compose and this Terraform-provisioned RDS instance sees the same
  # connection shape.
  db_username = "golem"
  db_name     = "golem_defender"
}

resource "aws_db_subnet_group" "this" {
  name       = var.name
  subnet_ids = var.subnet_ids
  tags       = var.tags
}

# Force encrypted PostgreSQL client connections at the database engine layer.
resource "aws_db_parameter_group" "this" {
  name   = "${var.name}-postgres${split(".", var.engine_version)[0]}"
  family = "postgres${split(".", var.engine_version)[0]}"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }

  tags = var.tags
}

# Pre-create RDS export log groups so retention and customer-managed encryption
# are enforced from the first exported PostgreSQL or engine-upgrade event.
resource "aws_cloudwatch_log_group" "postgresql" {
  name              = "/aws/rds/instance/${var.name}/postgresql"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
  tags              = var.tags
}

resource "aws_cloudwatch_log_group" "upgrade" {
  name              = "/aws/rds/instance/${var.name}/upgrade"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
  tags              = var.tags
}

resource "aws_db_instance" "this" {
  identifier                            = var.name
  engine                                = "postgres"
  engine_version                        = var.engine_version
  instance_class                        = var.instance_class
  allocated_storage                     = var.allocated_storage
  max_allocated_storage                 = coalesce(var.max_allocated_storage, var.allocated_storage * 5)
  storage_type                          = "gp3"
  storage_encrypted                     = true
  kms_key_id                            = var.kms_key_arn
  db_name                               = local.db_name
  username                              = local.db_username
  password                              = random_password.db.result
  multi_az                              = var.multi_az
  db_subnet_group_name                  = aws_db_subnet_group.this.name
  parameter_group_name                  = aws_db_parameter_group.this.name
  vpc_security_group_ids                = var.security_group_ids
  backup_retention_period               = var.backup_retention_days
  backup_window                         = "03:00-04:00"
  maintenance_window                    = "sun:04:30-sun:05:30"
  deletion_protection                   = var.deletion_protection
  skip_final_snapshot                   = !var.deletion_protection
  final_snapshot_identifier             = var.deletion_protection ? "${var.name}-final-${random_id.final_snapshot.hex}" : null
  delete_automated_backups              = false
  publicly_accessible                   = false
  auto_minor_version_upgrade            = true
  iam_database_authentication_enabled   = true
  copy_tags_to_snapshot                 = true
  performance_insights_enabled          = true
  performance_insights_kms_key_id       = var.kms_key_arn
  performance_insights_retention_period = var.performance_insights_retention_days
  monitoring_interval                   = var.monitoring_interval_seconds
  monitoring_role_arn                   = aws_iam_role.monitoring.arn
  enabled_cloudwatch_logs_exports       = ["postgresql", "upgrade"]
  apply_immediately                     = var.apply_immediately
  tags                                  = var.tags

  depends_on = [
    aws_iam_role_policy_attachment.monitoring,
    aws_cloudwatch_log_group.postgresql,
    aws_cloudwatch_log_group.upgrade,
  ]
}

data "aws_iam_policy_document" "proxy_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["rds.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "proxy" {
  permissions_boundary = var.permissions_boundary_arn
  name                 = "${var.name}-proxy"
  assume_role_policy   = data.aws_iam_policy_document.proxy_assume.json
  tags                 = var.tags
}

resource "aws_iam_role_policy" "proxy" {
  role = aws_iam_role.proxy.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = aws_secretsmanager_secret.db.arn
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = var.kms_key_arn
      }
    ]
  })
}

resource "aws_db_proxy" "this" {
  name                   = var.name
  engine_family          = "POSTGRESQL"
  role_arn               = aws_iam_role.proxy.arn
  vpc_subnet_ids         = var.subnet_ids
  vpc_security_group_ids = var.security_group_ids
  require_tls            = true
  debug_logging          = false

  auth {
    auth_scheme = "SECRETS"
    secret_arn  = aws_secretsmanager_secret.db.arn
    iam_auth    = "DISABLED"
  }

  tags       = var.tags
  depends_on = [aws_iam_role_policy.proxy]
}

resource "aws_db_proxy_default_target_group" "this" {
  db_proxy_name = aws_db_proxy.this.name

  connection_pool_config {
    max_connections_percent      = 90
    max_idle_connections_percent = 50
    connection_borrow_timeout    = 120
  }
}

resource "aws_db_proxy_target" "this" {
  db_instance_identifier = aws_db_instance.this.identifier
  db_proxy_name          = aws_db_proxy.this.name
  target_group_name      = aws_db_proxy_default_target_group.this.name
}

resource "aws_secretsmanager_secret" "runtime" {
  #checkov:skip=CKV2_AWS_57:The runtime secret contains only DATABASE_URL, rotated together with the database secret above through the same RDS Proxy credential runbook rather than an independent Lambda.
  name                    = "${var.name}/runtime"
  kms_key_id              = var.kms_key_arn
  recovery_window_in_days = var.secret_recovery_window_days
  tags                    = var.tags
}

# golem-backend (ui/backend/app/db.py) reads DATABASE_URL directly as a SQLAlchemy
# connection string -- see terraform/README.md for how this secret is wired into
# the ECS task definition's `secrets` map.
resource "aws_secretsmanager_secret_version" "runtime" {
  secret_id = aws_secretsmanager_secret.runtime.id
  secret_string = jsonencode({
    DATABASE_URL = "postgresql+psycopg://${local.db_username}:${random_password.db.result}@${aws_db_proxy.this.endpoint}:5432/${local.db_name}"
  })
}
