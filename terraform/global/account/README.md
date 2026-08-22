# Account security and Terraform control-plane foundation

> **Author:** Stan Zvenigorodskiy
> **Organization:** DevOps Lab Inc.
> **Website:** [DevOpsLabInc.com](https://DevOpsLabInc.com)

This one-time Terraform root owns resources that are singletons at the AWS
account or account/region level and provides the GitHub roles needed to
operate the environment stacks safely. Adapted from
`demand-gig-engine/terraform/global/account` -- see `terraform/README.md`'s
global/account scope decision for why this layer exists at all for a V1
self-sufficient stack.

## Controls owned here

- GitHub Actions IAM OIDC provider.
- Read-only Terraform plan role that can manage only native S3 `.tflock` files.
- Protected Terraform apply role using `PowerUserAccess` plus narrowly scoped IAM lifecycle permissions -- not `AdministratorAccess`.
- Regional GuardDuty detector.
- Optional AWS Organizations auto-enrollment for all existing and future member accounts when this stack runs in the delegated GuardDuty administrator account.
- GuardDuty S3 data-event, EBS malware, and RDS login protections.
- Optional GuardDuty Runtime Monitoring with automatic ECS Fargate agent management.
- Optional Inspector-backed ECR enhanced continuous scanning.

Environment stacks create only application-release roles and read the
shared OIDC provider and GuardDuty detector as data sources when needed.

Set `enable_guardduty_organization_auto_enrollment = true` only in the
delegated GuardDuty administrator account. Keep the default `false` in an
ordinary workload account; AWS rejects organization-configuration updates
from non-administrator accounts.

## Adapted from demand-gig-engine, not a byte-for-byte copy

Two things present in the vendored original are dropped here, since Golem
has no matching workload (see `terraform/README.md`'s explicit out-of-
scope list):

- The **ElastiCache service-linked role** (`aws_iam_service_linked_role.elasticache`)
  and the narrowly scoped `iam:PutRolePolicy` statement that exists only
  to let Terraform maintain it. Golem has no Redis/ElastiCache workload.
- The **`replication.ecr.amazonaws.com`** entry in the apply role's
  `CreateApprovedServiceLinkedRoles` allowlist. Golem's `modules/ecr`
  instantiation does not configure cross-region replication.

Everything else -- the OIDC provider, GuardDuty detector and features, ECR
enhanced-scanning toggle, and the plan/apply role trust and permission
boundaries -- is unchanged, with `project_name`/`github_repo` defaults
updated to `golem` and the RDS service-linked role kept (Golem's
`modules/rds_postgres` needs it).

## One-time bootstrap

The initial apply requires trusted local or administrative AWS credentials
because GitHub OIDC and its roles do not exist yet.

```bash
./terraform/scripts/bootstrap.sh account
terraform -chdir=terraform/global/account init -backend-config=backend.hcl
terraform -chdir=terraform/global/account plan
terraform -chdir=terraform/global/account apply
```

Then record the role outputs:

```bash
terraform -chdir=terraform/global/account output -raw terraform_plan_role_arn
terraform -chdir=terraform/global/account output -raw terraform_apply_role_arn
terraform -chdir=terraform/global/account output -raw terraform_permissions_boundary_arn
```

Configure these as GitHub Actions secrets whenever a CI workflow is added
(none exists in this repository yet -- this layer only prepares the trust
relationship a future workflow would use):

| Secret | Account-foundation output | Used by |
|---|---|---|
| `AWS_TERRAFORM_PLAN_ROLE_ARN` | `terraform_plan_role_arn` | Trusted post-merge development plans |
| `AWS_TERRAFORM_APPLY_ROLE_ARN` | `terraform_apply_role_arn` | Protected manual `dev`/`prod` deployments |

## Trust boundary

- Apply-role trust excludes pull-request subjects by default and uses protected `dev`/`prod` environment subjects.
- IAM mutations are limited to the exact `golem-dev-*` and `golem-prod-*` role namespaces; the plan/apply roles are outside that scope.
- Every environment-created role must retain the partition-correct AWS-managed `PowerUserAccess` permissions boundary, preventing IAM-administration escalation.
- Managed policy attachment is restricted to the two service-role policies actually consumed by `modules/backup` and `modules/rds_postgres`.
- `iam:PassRole` is separated and constrained to exact environment role prefixes plus Backup, CloudTrail, ECS tasks, RDS enhanced monitoring, and VPC Flow Logs service principals.
- The apply role deliberately lacks `iam:DeleteRolePermissionsBoundary`; removing a boundary requires a break-glass administrator.
- Service-linked role creation is constrained to the AWS services this framework actually uses.

## Lifecycle warnings

Do not destroy this stack during routine application teardown. Removing
the OIDC provider breaks GitHub-to-AWS federation. Removing the GuardDuty
detector disables detection and removes detector-owned findings.

Environment IAM roles are intentionally fail-closed: the Terraform apply
role cannot remove their permissions boundary. A full environment destroy
that reaches bounded IAM roles therefore requires an explicitly approved
break-glass administrator to remove the boundary only after the workload
has been decommissioned.

## Testing

`terraform fmt -recursive`, `terraform init -backend=false`, and
`terraform validate` all pass offline. This is a root stack, not a
reusable child module, so it has no `.tftest.hcl` suite of its own
(matching `demand-gig-engine/terraform/global/account`'s own structure).
`terraform apply` against this root has **not** been run against a real
AWS account in this work -- see `terraform/README.md`.
