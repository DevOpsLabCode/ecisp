# `ecr` Terraform module

> **Author:** Stan Zvenigorodskiy
> **Organization:** DevOps Lab Inc.
> **Website:** [DevOpsLabInc.com](https://DevOpsLabInc.com)

## Purpose

Creates Golem's two container repositories -- `golem-backend` and
`golem-iam-responder` -- with immutable tags, KMS encryption, and
scan-on-push. Vendored from `demand-gig-engine/terraform/modules/ecr`
with **no logic changes**.

## Inputs

| Name | Type | Required/default | Description |
|---|---|---|---|
| `name` | `string` | required | Stable repository prefix (Golem's root passes `local.name`, producing `<name>-backend` / `<name>-iam-responder`). |
| `repositories` | `set(string)` | required | Logical repository suffixes -- Golem passes `["backend", "iam-responder"]`. |
| `kms_key_arn` | `string` | required | Customer-managed KMS key ARN. |
| `retained_image_count` | `number` | `30` | Recent images retained per repository for rollback. |
| `force_delete` | `bool` | `false` | Allow deleting a non-empty repository; enable only for `dev`. |
| `tags` | `map(string)` | `{}` | Common ownership, environment, cost, and governance tags. |

## Outputs

| Name | Description |
|---|---|
| `repository_urls` | Map of repository suffix to push/pull URL, for CI image builds. |
| `repository_arns` | ARNs of every repository, granted to both ECS services' execution roles. |

## Usage

```hcl
module "ecr" {
  source       = "./modules/ecr"
  name         = local.name
  repositories = ["backend", "iam-responder"]
  kms_key_arn  = module.kms.key_arn
  force_delete = var.environment == "dev"
  tags         = local.tags
}
```

## Testing

```bash
terraform init -backend=false
terraform test
```

Runs entirely offline against a credential-free provider configuration.
