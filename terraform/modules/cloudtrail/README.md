# `cloudtrail` Terraform module

> **Author:** Stan Zvenigorodskiy
> **Organization:** DevOps Lab Inc.
> **Website:** [DevOpsLabInc.com](https://DevOpsLabInc.com)

## Purpose

Creates a multi-region CloudTrail trail with its own encrypted, versioned,
lifecycle-managed S3 bucket (logging into `modules/access_logs`'
centralized bucket), an encrypted SNS delivery-notification topic, and an
encrypted CloudWatch Logs group for near-real-time trail access. Vendored
from `demand-gig-engine/terraform/modules/cloudtrail` with **no logic
changes**.

## Inputs

| Name | Type | Required/default | Description |
|---|---|---|---|
| `name` | `string` | required | Stable name for the trail, log bucket, log group, SNS topic, and IAM role. |
| `kms_key_arn` | `string` | required | Customer-managed KMS key ARN. |
| `retention_days` | `number` | `365` | Lifecycle expiration for trail log objects (>= 90). |
| `access_log_bucket_id` | `string` | required | Centralized S3 access-log bucket this trail's own bucket logs into (see `modules/access_logs`). |
| `s3_data_event_bucket_arns` | `list(string)` | `[]` | Optional S3 buckets to capture object-level data events for. |
| `enable_insights` | `bool` | `false` | Enable CloudTrail Insights (adds billable events). |
| `permissions_boundary_arn` | `string` | required | AWS-managed `PowerUserAccess` policy ARN. |
| `tags` | `map(string)` | `{}` | Common ownership, environment, cost, and governance tags. |

## Outputs

| Name | Description |
|---|---|
| `trail_arn` | CloudTrail trail ARN. |
| `log_bucket_id` | S3 bucket storing CloudTrail's own delivered log objects. |
| `sns_topic_arn` | Encrypted SNS topic for delivery notifications. |

## Usage

```hcl
module "cloudtrail" {
  source                    = "./modules/cloudtrail"
  name                      = local.name
  kms_key_arn               = module.kms.key_arn
  retention_days            = var.cloudtrail_retention_days
  access_log_bucket_id      = module.access_logs.bucket_id
  enable_insights           = var.environment == "prod"
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
Bucket-policy and SNS-policy assertions that would otherwise depend on a
not-yet-created resource's own ARN are avoided in favor of resource-level
configuration checks -- see the comment at the top of `tests/main.tftest.hcl`.
