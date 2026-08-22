# `backup` Terraform module

> **Author:** Stan Zvenigorodskiy
> **Organization:** DevOps Lab Inc.
> **Website:** [DevOpsLabInc.com](https://DevOpsLabInc.com)

## Purpose

Creates an AWS Backup vault, daily backup plan, and resource selection
protecting Golem's RDS database (`module.database.db_arn`). Vendored from
`demand-gig-engine/terraform/modules/backup` with **no logic changes**.

## Vault Lock default-off decision

`enable_vault_lock` defaults to `false`, matching the vendored original.
Golem's own containment build plan carries an "immutable backups" theme
that makes Compliance-mode Vault Lock a natural fit conceptually -- but
Vault Lock is **irreversible once its grace period (`vault_lock_changeable_for_days`)
elapses**: no one, including AWS, can shorten retention or delete the vault
before recovery points expire. Forcing it on for a first-time deploy to a
brand-new account would make an operator's first mistake (wrong retention
value, wrong resource selection, wanting to tear the whole stack down
during evaluation) permanent. `envs/dev/terraform.tfvars` explicitly sets
`enable_backup_vault_lock = false`; a production environment that has
validated its retention requirements can set it to `true` deliberately.

## Inputs

| Name | Type | Required/default | Description |
|---|---|---|---|
| `name` | `string` | required | Stable name for the backup vault and plan. |
| `kms_key_arn` | `string` | required | Customer-managed KMS key ARN. |
| `resource_arns` | `list(string)` | required | Protected resource ARNs (Golem: `[module.database.db_arn]`). |
| `schedule_expression` | `string` | `cron(0 5 ? * * *)` | AWS Backup schedule. |
| `minimum_retention_days` | `number` | `35` | Normal deletion age / Vault Lock minimum. |
| `maximum_retention_days` | `number` | `3650` | Vault Lock maximum. |
| `cold_storage_after_days` | `number` | `null` | Days before cold-storage transition; null disables it. |
| `enable_vault_lock` | `bool` | `false` | See decision above. |
| `vault_lock_changeable_for_days` | `number` | `3` | Grace period before Vault Lock becomes immutable (>= 3). |
| `permissions_boundary_arn` | `string` | required | AWS-managed `PowerUserAccess` policy ARN. |
| `tags` | `map(string)` | `{}` | Common ownership, environment, cost, and governance tags. |

## Outputs

| Name | Description |
|---|---|
| `vault_name` | Backup vault name. |
| `vault_arn` | Backup vault ARN. |
| `plan_id` | Backup plan ID. |
| `vault_lock_enabled` | Echoes `var.enable_vault_lock`, for downstream documentation/output. |

## Usage

```hcl
module "backup" {
  source                    = "./modules/backup"
  name                      = local.name
  kms_key_arn               = module.kms.key_arn
  resource_arns             = [module.database.db_arn]
  enable_vault_lock         = var.enable_backup_vault_lock
  minimum_retention_days    = var.backup_retention_days
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
