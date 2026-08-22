# `alb` Terraform module (Golem-custom)

> **Author:** Stan Zvenigorodskiy
> **Organization:** DevOps Lab Inc.
> **Website:** [DevOpsLabInc.com](https://DevOpsLabInc.com)

## Purpose

Internet-facing Application Load Balancer, listeners, S3 access logging,
and the `golem-backend` target group.

## Why this is a custom module, not a vendored one

`demand-gig-engine/terraform/modules/alb` has a `certificate_arn == null`
branch built for a CloudFront-fronted deployment: when no regional ACM
certificate exists for the ALB's own AWS-generated hostname, HTTP traffic
is only forwarded to the target group if it carries an
`X-Origin-Verify` header that only CloudFront (configured with the
matching secret) ever sends. Golem V1 has no CDN in front of its ALB (see
`terraform/README.md`'s explicit out-of-scope list and its ALB/certificate
decision). Reusing that branch unmodified would make the ALB permanently
unreachable by design -- nothing would ever send the header.

This module's no-certificate branch (`aws_lb_listener.http_direct`)
instead forwards HTTP directly and unconditionally to the target group.
This is a deliberate, accepted trade-off for a V1 self-sufficient
deployment: **with no `certificate_arn` configured, traffic between the
client and the ALB is plaintext HTTP and does not require a shared
secret** -- acceptable for a quick trial or an internal/VPN-only rollout,
not for a real production deployment with sensitive data in transit.
Configure `certificate_arn` (an ACM certificate for a domain you own,
issued and DNS-validated outside this stack -- see `terraform/README.md`)
to get the HTTPS listener and the HTTP-to-HTTPS redirect instead.

The target group's port and health-check path are also parameterized
(`target_port`, `health_check_path`, defaulting to `8000` and
`/api/health` to match `golem-backend`'s actual FastAPI health endpoint,
`ui/backend/app/main.py`'s `GET /api/health`) rather than hardcoded, since
Golem's copy of this module only ever serves one application.

## Inputs

| Name | Type | Required/default | Description |
|---|---|---|---|
| `name` | `string` | required | ALB and target-group name prefix. |
| `vpc_id` | `string` | required | VPC ID that owns the target group. |
| `subnet_ids` | `list(string)` | required | Public subnet IDs (>= 2 AZs). |
| `security_group_ids` | `list(string)` | required | Security groups attached to the ALB. |
| `certificate_arn` | `string` | `null` | Regional ACM certificate for the HTTPS listener; `null` runs the HTTP-only trial fallback described above. |
| `target_port` | `number` | `8000` | Backend container port the target group forwards to. |
| `health_check_path` | `string` | `/api/health` | HTTP path the target group's health check requests. |
| `deletion_protection` | `bool` | `true` | Reject accidental ALB deletion. |
| `access_log_bucket_id` | `string` | required | Centralized S3 access-log bucket name (see `modules/access_logs`). |
| `access_log_prefix` | `string` | `"alb"` | Relative S3 prefix matching the log bucket's delivery policy. |
| `tags` | `map(string)` | `{}` | Common ownership, environment, cost, and governance tags. |

## Outputs

| Name | Description |
|---|---|
| `arn` | ALB ARN. |
| `dns_name` | AWS-generated ALB hostname -- Golem's application URL when no custom domain is configured. |
| `zone_id` | ALB's Route 53 hosted-zone ID, for a future alias record. |
| `target_group_arn` | Target-group ARN registered with the `golem-backend` ECS service. |
| `target_group_arn_suffix` | Target-group ARN suffix used by CloudWatch alarm/dashboard dimensions. |

## Usage

```hcl
module "alb" {
  source                = "./modules/alb"
  name                  = local.name
  vpc_id                = module.networking.vpc_id
  subnet_ids            = module.networking.public_subnet_ids
  security_group_ids    = [module.security.alb_sg_id]
  certificate_arn       = var.certificate_arn # null runs the HTTP-only V1 trial fallback
  deletion_protection   = var.deletion_protection
  access_log_bucket_id  = module.access_logs.bucket_id
  tags                  = local.tags
}
```

## Testing

```bash
terraform init -backend=false
terraform test
```

Runs entirely offline against a credential-free provider configuration.
