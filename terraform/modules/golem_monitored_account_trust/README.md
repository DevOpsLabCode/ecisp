# `golem_monitored_account_trust` Terraform module

> **Author:** Stan Zvenigorodskiy
> **Organization:** DevOps Lab Inc.
> **Website:** [DevOpsLabInc.com](https://DevOpsLabInc.com)

## Purpose — the trust half of Tier 4's cross-account IAM revocation

Applied once per AWS account that Golem Defender monitors, by that
account's own operators (not by Golem). Creates the role Golem's
`iam-responder` (see `../../../iam-responder/`) assumes into this account
to revoke a compromised workload's IAM permissions, and nothing else --
its own execution identity in Golem's security-tooling account is a
separate module, [`golem_iam_responder_execution`](../golem_iam_responder_execution/),
applied on the other side of the trust relationship.

## Why two separate modules, not one

This mirrors the containment build plan's core privilege-separation
principle: the in-cluster responder and the IAM-revocation component must
never share a credential, and by the same reasoning, the trust
relationship itself is defined from both sides independently rather than
as one shared piece of Terraform. A monitored account's operators apply
*this* module and never need to know or configure anything about how
`iam-responder` is deployed; Golem's own operators apply
`golem_iam_responder_execution` and never need write access to a
monitored account's Terraform state.

## What this grants, and what it deliberately does not

- **Trust**: only `var.trusted_principal_arn` -- an exact IAM role ARN,
  never an account root -- may assume the created role, optionally also
  requiring `var.external_id` (see below).
- **Permissions**: `iam:PutRolePolicy` / `iam:DeleteRolePolicy`, scoped to
  `arn:aws:iam::<this account>:role/<monitored_role_name_prefix>*` --
  even a fully compromised `iam-responder` can only ever attach or remove
  the deny-all policy on roles matching this naming convention, never an
  arbitrary IAM role in this account. Plus `iam:ListAccountAliases` on
  `*`, which has no meaningful resource to scope and exists solely so the
  coverage sweep (`iam-responder/app/account_coverage.py`) has something
  harmless to call to confirm the session works at all.
- **Nothing else.** No read access to this account's other resources, no
  access to roles outside the configured prefix, no permissions boundary
  unless you set one explicitly.

## On external IDs and the confused-deputy problem

AWS's own guidance for any cross-account role a *third party* assumes
(which is exactly this relationship -- Golem is a third party from this
account's perspective) recommends an external ID: a shared secret the
trusting account requires on every `AssumeRole` call, so that a Golem
customer (or, in Golem's future SaaS form, a completely different
tenant's account) can't trick `iam-responder` into assuming a role it
wasn't meant to. This module makes `var.external_id` optional -- applying
without one is a valid, deliberate choice for a low-risk trial setup, and
the module still applies cleanly (a `check` block warns, but does not
block, the plan/apply) -- but sets one before production use.

## Inputs

| Name | Type | Required/default | Sensitive | Description |
|---|---|---|---|---|
| `trusted_principal_arn` | `string` | `required` | `false` | Exact IAM role ARN of Golem's iam-responder execution identity. |
| `external_id` | `string` | `""` | `true` | Optional STS external ID required on every AssumeRole call into this role. |
| `role_name` | `string` | `"golem-iam-responder"` | `false` | Name of the role Golem's iam-responder assumes into this account. |
| `monitored_role_name_prefix` | `string` | `"golem-monitored-"` | `false` | Naming convention this account's own workload roles must follow to be revocable by Golem. |
| `permissions_boundary_arn` | `string` | `null` | `false` | Optional permissions boundary applied to the created role. |
| `tags` | `map(string)` | `{}` | `false` | Common ownership, environment, cost, and governance tags. |

## Outputs

| Name | Description |
|---|---|
| `role_arn` | ARN of the role Golem's iam-responder assumes into this account -- register this account's `account_id` with Golem via `POST /api/aws-accounts` once applied. |
| `role_name` | Bare name of that role. |

## Usage

```hcl
module "golem_trust" {
  source = "github.com/DevOpsLabCode/golem//terraform/modules/golem_monitored_account_trust"

  trusted_principal_arn = "arn:aws:iam::<golem-security-tooling-account>:role/golem-iam-responder-execution"
  external_id           = var.golem_external_id # a secret Golem gives you when you onboard

  tags = {
    ManagedBy = "terraform"
    Owner     = "platform-security"
  }
}
```

After applying, register this account with Golem so its coverage sweep
starts tracking it:

```bash
curl -X POST https://golem.example.com/api/aws-accounts \
  -H "Content-Type: application/json" \
  -d "{\"account_id\": \"$(aws sts get-caller-identity --query Account --output text)\"}"
```

Every workload role you want Golem able to contain during a real incident
must be named with the `monitored_role_name_prefix` you configured (e.g.
`golem-monitored-payments-service`) -- an unprefixed role is invisible to
this trust relationship entirely, by design.

## Testing

```bash
terraform init -backend=false
terraform test
```

Runs entirely offline against a credential-free provider configuration --
`aws_iam_policy_document` is always computed locally by the AWS provider
(never a real API call), so no AWS account or credentials are needed to
verify the trust policy, permission policy, and validation logic this
module produces.
