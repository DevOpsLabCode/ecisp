# `access_logs` Terraform module

> **Author:** Stan Zvenigorodskiy
> **Organization:** DevOps Lab Inc.
> **Website:** [DevOpsLabInc.com](https://DevOpsLabInc.com)

## Purpose

Creates the single terminal S3 bucket that `modules/alb`'s ALB access logs
and `modules/cloudtrail`'s S3 server-access logs are both delivered into --
encrypted, versioned, public-access-blocked, with a lifecycle policy and
an explicit deny of any non-TLS request.

## Adapted from demand-gig-engine, not a byte-for-byte copy

`demand-gig-engine/terraform/modules/access_logs` also grants CloudFront's
documented legacy standard-logging canonical user `FULL_CONTROL` via an
explicit bucket ACL (CloudFront's classic log delivery mechanism predates
IAM-policy-based delivery and still requires it). Golem V1 has no
CloudFront distribution at all (see `terraform/README.md`), so that ACL
grant, the `aws_canonical_user_id` data source it depends on, and the
`bucket_domain_name` output that only existed for CloudFront's logging
config are all dropped. Everything else -- the ALB delivery policy,
encryption, versioning, lifecycle, public-access block, and
insecure-transport deny -- is unchanged.

## Inputs

| Name | Type | Required/default | Description |
|---|---|---|---|
| `name` | `string` | required | Globally unique S3 bucket name. |
| `force_destroy` | `bool` | `false` | Allow deleting a non-empty bucket; enable only for `dev`. |
| `alb_prefix` | `string` | `"alb"` | S3 prefix used by ALB access-log delivery. |
| `retention_days` | `number` | `365` | Retention for current log objects. |
| `noncurrent_version_expiration_days` | `number` | `90` | Retention for superseded log-object versions. |
| `tags` | `map(string)` | `{}` | Common ownership, environment, cost, and governance tags. |

## Outputs

| Name | Description |
|---|---|
| `bucket_id` | Bucket name, passed to `modules/alb`'s `access_log_bucket_id` and `modules/cloudtrail`'s `access_log_bucket_id`. |
| `bucket_arn` | Bucket ARN. |

## Usage

```hcl
module "access_logs" {
  source        = "./modules/access_logs"
  name          = "${local.name}-${data.aws_caller_identity.current.account_id}-access-logs"
  force_destroy = var.environment == "dev"
  tags          = local.tags
}
```

## Testing

```bash
terraform init -backend=false
terraform test
```

Runs entirely offline against a credential-free provider configuration --
`aws_iam_policy_document` is always computed locally by the AWS provider;
`aws_caller_identity` is overridden in the test file.
