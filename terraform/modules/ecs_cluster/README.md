# `ecs_cluster` Terraform module

> **Author:** Stan Zvenigorodskiy
> **Organization:** DevOps Lab Inc.
> **Website:** [DevOpsLabInc.com](https://DevOpsLabInc.com)

## Purpose

Creates the single ECS cluster Golem's `golem-backend` and
`golem-iam-responder` services both run in, with enhanced Container
Insights and encrypted, retained ECS Exec audit logging. Vendored from
`demand-gig-engine/terraform/modules/ecs_cluster` with **no logic
changes** -- this module has no product-specific coupling.

## Inputs

| Name | Type | Required/default | Description |
|---|---|---|---|
| `name` | `string` | required | ECS cluster and ECS Exec log-group name. |
| `kms_key_arn` | `string` | required | Customer-managed KMS key ARN used by ECS Exec and its log group. |
| `log_retention_days` | `number` | `365` | ECS Exec log retention. |
| `tags` | `map(string)` | `{}` | Common ownership, environment, cost, and governance tags. |

## Outputs

| Name | Description |
|---|---|
| `cluster_arn` | ARN of the ECS cluster. |
| `cluster_name` | Name of the ECS cluster. |

## Usage

```hcl
module "cluster" {
  source      = "./modules/ecs_cluster"
  name        = local.name
  kms_key_arn = module.kms.key_arn
  tags        = local.tags
}
```

## Testing

```bash
terraform init -backend=false
terraform test
```

Runs entirely offline against a credential-free provider configuration.
