# `security` Terraform module (Golem-custom)

> **Author:** Stan Zvenigorodskiy
> **Organization:** DevOps Lab Inc.
> **Website:** [DevOpsLabInc.com](https://DevOpsLabInc.com)

## Purpose

Least-privilege security groups for Golem's ALB, ECS tasks, and PostgreSQL.

## Why this is a custom module, not a vendored one

`demand-gig-engine/terraform/modules/security` restricts its ALB security
group's ingress to the AWS-managed CloudFront origin-facing prefix list, and
also creates a `redis` security group. Golem V1 has neither a CloudFront
edge nor a cache layer (see `terraform/README.md`'s explicit out-of-scope
list), so this module diverges from that original in exactly two ways:

1. **No CloudFront prefix list.** The `alb` security group allows plain
   internet ingress on 443 (and 80, for the redirect-to-HTTPS or
   direct-forward listener -- see `modules/alb`) instead of only the
   CloudFront origin-facing managed prefix list. There is nothing in front
   of Golem's ALB to inject a verification header, so restricting to a
   CloudFront-only prefix list would make the ALB unreachable by design.
2. **No `redis` security group.** Golem has no ElastiCache/Redis workload.

The `app` and `db` security groups are otherwise identical to the vendored
original: `app` accepts ingress only from `alb`, `db` accepts ingress only
from `app` (plus proxy-to-database traffic within the group itself) on 5432.

## Inputs

| Name | Type | Required/default | Description |
|---|---|---|---|
| `name` | `string` | required | Stable name prefix used for security-group names and tags. |
| `vpc_id` | `string` | required | ID of the VPC that owns every security group. |
| `vpc_cidr` | `string` | required | Private VPC CIDR used to constrain east-west egress rules. |
| `app_port` | `number` | `8000` | Application TCP port allowed between the ALB and ECS tasks. |
| `tags` | `map(string)` | `{}` | Common ownership, environment, cost, and governance tags. |

## Outputs

| Name | Description |
|---|---|
| `alb_sg_id` | Security group attached to the ALB. |
| `app_sg_id` | Security group attached to ECS task ENIs (backend, iam-responder). |
| `db_sg_id` | Security group attached to the RDS instance and RDS Proxy. |

## Usage

```hcl
module "security" {
  source   = "./modules/security"
  name     = local.name
  vpc_id   = module.networking.vpc_id
  vpc_cidr = var.vpc_cidr
  tags     = local.tags
}
```

## Testing

```bash
terraform init -backend=false
terraform test
```

Runs entirely offline against a credential-free provider configuration.
