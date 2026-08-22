# `rds_postgres` Terraform module

> **Author:** Stan Zvenigorodskiy
> **Organization:** DevOps Lab Inc.
> **Website:** [DevOpsLabInc.com](https://DevOpsLabInc.com)

## Purpose

Provisions the encrypted, Multi-AZ-capable PostgreSQL instance behind
Golem's `golem-backend` API (`ui/backend/app/db.py`), fronted by RDS Proxy,
with enhanced monitoring, Performance Insights, forced TLS, and two
Secrets Manager secrets.

## Adapted from demand-gig-engine, not a byte-for-byte copy

The architecture (RDS instance + RDS Proxy + a database-credential secret
+ a runtime-connection secret) is identical to
`demand-gig-engine/terraform/modules/rds_postgres`. Two literals differ:

- **Database name and username** are `golem_defender` / `golem`, matching
  `ui/docker-compose.yml`'s `DATABASE_URL` convention exactly, instead of
  demand-gig-engine's `gigengine` / `gigadmin`.
- **The runtime secret contains only `DATABASE_URL`.** The vendored
  original also generates a Django `SECRET_KEY` into the same secret;
  golem-backend is a FastAPI/SQLAlchemy service with no equivalent
  concept (confirmed: no `SECRET_KEY` reference anywhere under
  `ui/backend/app/`), so that generation and field are dropped rather than
  carried over unused.

`DATABASE_URL` is built as `postgresql+psycopg://...` -- golem-backend
pins `psycopg[binary]==3.2.10` (psycopg **3**, not the `psycopg2` that a
bare `postgresql://` SQLAlchemy URL resolves to by default), matching
`ui/docker-compose.yml`'s own DSN scheme exactly.

## Inputs

| Name | Type | Required/default | Description |
|---|---|---|---|
| `name` | `string` | required | Stable identifier for the database, proxy, subnet group, roles, and secrets. |
| `subnet_ids` | `list(string)` | required | Private database subnet IDs (>= 2 AZs). |
| `security_group_ids` | `list(string)` | required | Security groups attached to the RDS instance and proxy. |
| `kms_key_arn` | `string` | required | Customer-managed KMS key ARN. |
| `engine_version` | `string` | `"17"` | PostgreSQL engine version. |
| `instance_class` | `string` | required | RDS instance class, e.g. `db.t4g.micro`. |
| `allocated_storage` | `number` | required | Initial gp3 storage in GiB (>= 20). |
| `max_allocated_storage` | `number` | `null` | Max autoscaled storage; null uses 5x initial. |
| `multi_az` | `bool` | `true` | Synchronous standby in another AZ. |
| `backup_retention_days` | `number` | `30` | Automated backup / PITR retention (1-35). |
| `performance_insights_retention_days` | `number` | `731` | `7` or `731`. |
| `log_retention_days` | `number` | `365` | CloudWatch retention for exported RDS logs. |
| `monitoring_interval_seconds` | `number` | `60` | Enhanced Monitoring interval. |
| `deletion_protection` | `bool` | `true` | Reject accidental deletion. |
| `apply_immediately` | `bool` | `false` | Apply changes immediately vs. maintenance window. |
| `secret_recovery_window_days` | `number` | `30` | Secrets Manager deletion recovery window. |
| `permissions_boundary_arn` | `string` | required | AWS-managed `PowerUserAccess` policy ARN. |
| `tags` | `map(string)` | `{}` | Common ownership, environment, cost, and governance tags. |

## Outputs

| Name | Description |
|---|---|
| `endpoint` | Direct RDS writer endpoint (no port). |
| `proxy_endpoint` | RDS Proxy endpoint -- what `golem-backend` should actually connect through. |
| `secret_arn` | Sensitive. Database-credential secret ARN (used by RDS Proxy's own auth). |
| `db_arn` | RDS instance ARN, consumed by `modules/backup`. |
| `db_identifier` | RDS identifier, consumed by `modules/cloudwatch`. |
| `runtime_secret_arn` | Sensitive. Secret containing `DATABASE_URL`, wired into `golem-backend`'s ECS task `secrets` map. |

## Usage

```hcl
module "database" {
  source                    = "./modules/rds_postgres"
  name                      = local.name
  subnet_ids                = module.networking.db_subnet_ids
  security_group_ids        = [module.security.db_sg_id]
  kms_key_arn               = module.kms.key_arn
  instance_class            = var.db_instance_class
  allocated_storage         = var.db_allocated_storage
  multi_az                  = var.db_multi_az
  deletion_protection       = var.deletion_protection
  permissions_boundary_arn  = local.permissions_boundary_arn
  tags                      = local.tags
}
```

## Testing

```bash
terraform init -backend=false
terraform test
```

Runs entirely offline against a credential-free provider configuration.
