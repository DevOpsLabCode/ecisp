# `networking` Terraform module

> **Author:** Stan Zvenigorodskiy
> **Organization:** DevOps Lab Inc.
> **Website:** [DevOpsLabInc.com](https://DevOpsLabInc.com)

## Purpose

Builds the VPC Golem's root stack runs in: a three-tier subnet layout
(public, private-app, private-db) spread across `az_count` Availability
Zones, resilient NAT egress, an S3 gateway endpoint for private ECR/S3
traffic, and encrypted VPC Flow Logs. Vendored from
`demand-gig-engine/terraform/modules/networking` with **no logic changes**
-- this module has no CloudFront or product-specific coupling, so it is
reused as-is (see `terraform/README.md`).

## Inputs

| Name | Type | Required/default | Description |
|---|---|---|---|
| `name` | `string` | required | Stable VPC, subnet, route, log-group, and IAM role name prefix. |
| `cidr` | `string` | required | IPv4 VPC CIDR (`/20` or larger) from which the three subnet tiers are derived. |
| `az_count` | `number` | required | Number of Availability Zones (2 or 3) used by each subnet tier. |
| `nat_gateway_per_az` | `bool` | `false` | One NAT gateway per AZ (resilient) vs. one shared NAT gateway (cheap, dev). |
| `kms_key_arn` | `string` | required | Customer-managed KMS key used by the VPC flow-log group. |
| `flow_log_retention_days` | `number` | `365` | CloudWatch retention for VPC flow records. |
| `permissions_boundary_arn` | `string` | required | AWS-managed `PowerUserAccess` policy ARN applied to the flow-logs IAM role. |
| `tags` | `map(string)` | `{}` | Common ownership, environment, cost, and governance tags. |

## Outputs

| Name | Description |
|---|---|
| `vpc_id` | VPC ID. |
| `public_subnet_ids` | Public subnet IDs (ALB, NAT gateways). |
| `app_subnet_ids` | Private application subnet IDs (ECS Fargate tasks). |
| `db_subnet_ids` | Private database subnet IDs (RDS PostgreSQL, RDS Proxy). |

## Usage

```hcl
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
```

## Testing

```bash
terraform init -backend=false
terraform test
```

Runs entirely offline against a credential-free provider configuration.
`data.aws_availability_zones` is overridden with a fixed AZ list so the test
run needs no real AWS API call.
