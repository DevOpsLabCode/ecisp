# `secrets_manager` Terraform module

> **Author:** Stan Zvenigorodskiy
> **Organization:** DevOps Lab Inc.
> **Website:** [DevOpsLabInc.com](https://DevOpsLabInc.com)

## Purpose

Creates one encrypted, pre-seeded JSON secret holding `IAM_RESPONDER_API_KEY`
-- the fleet-wide bearer credential `golem-iam-responder` authenticates to
`golem-backend` with (see `iam-responder/app/backend_client.py` and
`ui/backend/app/main.py`'s `_authenticated_iam_component`). A random
48-character value is generated on first apply so the secret is never
created empty; `ignore_changes` on `secret_string` means a later manual
rotation (console, CLI) is never clobbered by a subsequent `terraform
apply`.

Adapted from `demand-gig-engine/terraform/modules/secrets_manager` -- same
architecture (one pre-seeded secret container), different key set:
demand-gig-engine's version seeds 16 empty OAuth/payment/Meta provider
keys meant to be filled in by hand later; Golem needs exactly one key,
and it can be usefully random from the start since both consumers of it
(`golem-backend`, `golem-iam-responder`) are Terraform-managed ECS
services that read it from the same secret rather than a human typing it
into a form.

## Inputs

| Name | Type | Required/default | Description |
|---|---|---|---|
| `name` | `string` | required | Secret path prefix. |
| `kms_key_arn` | `string` | required | Customer-managed KMS key ARN. |
| `recovery_window_in_days` | `number` | `30` | Secrets Manager deletion recovery window (7-30). |
| `tags` | `map(string)` | `{}` | Common ownership, environment, cost, and governance tags. |

## Outputs

| Name | Description |
|---|---|
| `secret_arn` | Sensitive. ARN of the secret containing `IAM_RESPONDER_API_KEY`, wired into both ECS services' `secrets` map. |

## Usage

```hcl
module "secrets_manager" {
  source                  = "./modules/secrets_manager"
  name                    = local.name
  kms_key_arn             = module.kms.key_arn
  recovery_window_in_days = var.environment == "prod" ? 30 : 7
  tags                    = local.tags
}
```

## Testing

```bash
terraform init -backend=false
terraform test
```

Runs entirely offline against a credential-free provider configuration.
