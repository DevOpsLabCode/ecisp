# `kms` Terraform module

> **Author:** Stan Zvenigorodskiy
> **Organization:** DevOps Lab Inc.
> **Website:** [DevOpsLabInc.com](https://DevOpsLabInc.com)

## Purpose

Creates the single customer-managed KMS key Golem's root stack uses to encrypt
application data, CloudWatch/VPC-flow/CloudTrail logs, Secrets Manager
secrets, RDS storage, and SNS alarm/notification topics. One key per
environment keeps the key policy's account-administration statement simple
and keeps key-rotation and deletion-window decisions environment-scoped.

Vendored from `demand-gig-engine/terraform/modules/kms` with no logic
changes other than dropping the EventBridge Scheduler grant statement, which
existed only for demand-gig-engine's campaign-expiry schedule -- Golem's V1
root stack has no EventBridge Scheduler use (see `terraform/README.md`).

## Inputs

| Name | Type | Required/default | Description |
|---|---|---|---|
| `name` | `string` | required | KMS alias suffix and key-policy CloudTrail name scope. |
| `deletion_window` | `number` | `30` | Recovery window in days (7-30) before scheduled key deletion becomes permanent. |
| `tags` | `map(string)` | `{}` | Common ownership, environment, cost, and governance tags. |

## Outputs

| Name | Description |
|---|---|
| `key_arn` | ARN of the customer-managed key. |
| `key_id` | Key ID of the customer-managed key. |

## Usage

```hcl
module "kms" {
  source = "./modules/kms"
  name   = local.name
  tags   = local.tags
}
```

## Testing

```bash
terraform init -backend=false
terraform test
```

Runs entirely offline against a credential-free provider configuration --
`aws_iam_policy_document` is always computed locally by the AWS provider.
