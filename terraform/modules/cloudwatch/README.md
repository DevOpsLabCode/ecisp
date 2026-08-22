# `cloudwatch` Terraform module (Golem-simplified)

> **Author:** Stan Zvenigorodskiy
> **Organization:** DevOps Lab Inc.
> **Website:** [DevOpsLabInc.com](https://DevOpsLabInc.com)

## Purpose

Encrypted SNS alerting, ALB/ECS/RDS CloudWatch alarms, and a single
operational dashboard covering both of Golem's ECS services and its
database.

## Why this is a simplified module, not a vendored one

`demand-gig-engine/terraform/modules/cloudwatch` also alarms and
dashboards Redis (ElastiCache) and SQS (queue backlog, oldest-message age,
DLQ depth) metrics, and a CloudFront 5xx-rate alarm. Golem has none of
those components in V1 (no cache layer, no queue, no CDN -- see
`terraform/README.md`'s explicit out-of-scope list), so instantiating the
vendored module as-is would require either fabricating fake Redis/SQS/
CloudFront resources just to satisfy its required variables, or leaving
alarms permanently pointed at metrics that will never emit data. Neither
is acceptable, so this is a pruned copy: the SNS topic, ALB alarms
(5xx, unhealthy targets, p95 latency), ECS CPU/memory alarms (`for_each`
over `service_names`, unchanged), RDS CPU/free-storage alarms, and the
dashboard structure are all otherwise identical to the vendored original.

## Inputs

| Name | Type | Required/default | Description |
|---|---|---|---|
| `name` | `string` | required | Stable prefix for alarms, dashboard, and SNS topic. |
| `alb_arn_suffix` | `string` | required | ALB ARN suffix (`app/...`). |
| `target_group_arn_suffix` | `string` | required | Target-group ARN suffix (`targetgroup/...`). |
| `cluster_name` | `string` | required | ECS cluster name. |
| `service_names` | `map(string)` | required | Alarm keys mapped to ECS service names -- Golem passes `{ backend = ..., iam_responder = ... }`. |
| `db_identifier` | `string` | required | RDS identifier. |
| `sns_email` | `string` | `""` | Optional alarm-notification mailbox. |
| `kms_key_arn` | `string` | required | Customer-managed KMS key. |
| `account_root_arn` | `string` | required | Owning account root ARN. |
| `thresholds` | `object` | see `variables.tf` | Per-alarm thresholds (no redis/queue/cloudfront fields, unlike the vendored original). |
| `tags` | `map(string)` | `{}` | Common ownership, environment, cost, and governance tags. |

## Outputs

| Name | Description |
|---|---|
| `alarm_topic_arn` | Encrypted SNS topic ARN. |
| `dashboard_name` | CloudWatch dashboard name. |

## Usage

```hcl
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
  db_identifier     = module.database.db_identifier
  sns_email         = var.alarm_email
  kms_key_arn       = module.kms.key_arn
  account_root_arn  = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
  tags              = local.tags
}
```

## Testing

```bash
terraform init -backend=false
terraform test
```

Runs entirely offline against a credential-free provider configuration.
