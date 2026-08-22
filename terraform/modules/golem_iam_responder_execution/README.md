# `golem_iam_responder_execution` Terraform module

> **Author:** Stan Zvenigorodskiy
> **Organization:** DevOps Lab Inc.
> **Website:** [DevOpsLabInc.com](https://DevOpsLabInc.com)

## Purpose — the execution-side half of Tier 4's cross-account IAM revocation

Applied once, in Golem's own security-tooling AWS account, by Golem's own
operators. Creates a standalone IAM policy granting whatever compute
platform `iam-responder` (see `../../../iam-responder/`) actually runs on
permission to assume into any monitored account's trust role -- the other
side of the relationship `golem_monitored_account_trust` sets up in each
monitored account.

## Why a standalone policy, not a role

This module doesn't know or assume how `iam-responder` is deployed --
ECS Fargate task, EKS pod with IRSA, a plain EC2 instance for a first
trial, or something else entirely. Rather than creating a role tied to
one specific compute platform's trust model, it creates a policy and lets
the composition that actually deploys `iam-responder` attach it to
whatever execution role that deployment already needs. See the outputs
section for exactly how.

## What this grants

`sts:AssumeRole` on `arn:*:iam::*:role/<monitored_role_name>` -- a
wildcard account ID is unavoidable here, since the whole point is
reaching whichever accounts get registered with Golem *after* this policy
is created (via `POST /api/aws-accounts` on the backend), not a fixed
list known at Terraform apply time. `<monitored_role_name>` must exactly
match the `role_name` every `golem_monitored_account_trust` module
instance uses -- if a monitored account customizes its `role_name`, this
policy's `monitored_role_name` must be updated to match, or that
account's trust relationship becomes unreachable.

Nothing else. No access to any other AWS service, no wildcard beyond the
one narrow resource pattern above.

## Inputs

| Name | Type | Required/default | Description |
|---|---|---|---|
| `monitored_role_name` | `string` | `"golem-iam-responder"` | Role name every monitored account grants Golem -- must match `golem_monitored_account_trust`'s `role_name`. |
| `name` | `string` | `"golem-iam-responder-assume-monitored-accounts"` | Name of the standalone IAM policy this module creates. |
| `tags` | `map(string)` | `{}` | Common ownership, environment, cost, and governance tags. |

## Outputs

| Name | Description |
|---|---|
| `policy_arn` | Attach this to whatever IAM role `iam-responder` actually runs under. |

## Usage

```hcl
module "golem_iam_responder_execution" {
  source = "github.com/DevOpsLabCode/golem//terraform/modules/golem_iam_responder_execution"

  tags = {
    ManagedBy = "terraform"
    Owner     = "platform-security"
  }
}

# Wherever iam-responder's own execution role is created --
# e.g. an ECS task role:
resource "aws_iam_role_policy_attachment" "golem_iam_responder_assume" {
  role       = aws_iam_role.iam_responder_task.name
  policy_arn = module.golem_iam_responder_execution.policy_arn
}
```

`iam-responder`'s own `GOLEM_ASSUME_ROLE_TEMPLATE` env var (default
`arn:aws:iam::{account_id}:role/golem-iam-responder`, see
`iam-responder/README.md`) must reference the same `monitored_role_name`
configured here.

## Testing

```bash
terraform init -backend=false
terraform test
```

Runs entirely offline against a credential-free provider configuration --
this module has no data sources that need a real API call at all, so no
AWS account or credentials are needed to verify the policy this module
produces.
