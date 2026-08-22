# `global/bootstrap` -- protected Terraform state backend

> **Author:** Stan Zvenigorodskiy
> **Organization:** DevOps Lab Inc.
> **Website:** [DevOpsLabInc.com](https://DevOpsLabInc.com)

Creates the S3 bucket the root stack's own `terraform { backend "s3" {} }`
block depends on, before that bucket exists. Vendored from
`demand-gig-engine/terraform/global/bootstrap` with no logic changes.

- One customer-managed KMS key encrypting Terraform state.
- A protected, versioned, `prevent_destroy` state bucket using
  **S3-native locking** (`use_lockfile = true` in the generated
  `backend.hcl`, a Terraform >= 1.10 feature) -- **no DynamoDB lock table**.
- A separate S3-server-access-log bucket the state bucket logs into.

## Bootstrapping a brand-new account

This bucket doesn't exist yet on a fresh account, so it can't start with
an S3 backend -- `terraform/scripts/bootstrap.sh` (adapted from
`demand-gig-engine/scripts/bootstrap.sh`) handles the dance: apply this
root with **local** state first, read its `kms_key_arn` output, write a
generated `backend.hcl`, then `terraform init -migrate-state` into the
now-existing protected bucket. See `terraform/README.md` for the full
sequence and `scripts/bootstrap.sh` itself for the exact commands.

## Usage

```bash
./terraform/scripts/bootstrap.sh dev
# then, having generated envs/dev/backend.hcl:
terraform -chdir=terraform init -backend-config=envs/dev/backend.hcl
```

## Testing

`terraform fmt -recursive`, `terraform init -backend=false`, and
`terraform validate` all pass offline. This is a root stack, not a
reusable child module, so it has no `.tftest.hcl` suite of its own
(matching `demand-gig-engine/terraform/global/bootstrap`'s own structure).
`terraform apply` against this root has **not** been run against a real
AWS account in this work -- see `terraform/README.md`'s honest
unverified-without-real-AWS statement.
