# Golem Terraform

## What's here

Two reusable child modules implementing the two halves of Tier 4's
cross-account IAM revocation trust relationship (see the containment
build plan and `../iam-responder/README.md`):

- **[`modules/golem_monitored_account_trust`](modules/golem_monitored_account_trust/)**
  -- applied once per AWS account Golem monitors, by that account's own
  operators. Creates the role `iam-responder` assumes into that account.
- **[`modules/golem_iam_responder_execution`](modules/golem_iam_responder_execution/)**
  -- applied once, in Golem's own security-tooling account. Creates the
  policy granting `iam-responder`'s own execution identity permission to
  assume into any monitored account.

Both are genuinely reusable, independently tested (`terraform test`,
entirely offline -- see each module's own README), and validated against
a real Terraform CLI (`terraform fmt`, `terraform validate`).

## What's *not* here yet

**No root stack.** Both modules above need to be *called* from somewhere
-- a monitored account's own existing Terraform (for
`golem_monitored_account_trust`), and a root stack that actually deploys
`iam-responder` itself in Golem's security-tooling account (for
`golem_iam_responder_execution`, plus whatever compute platform
`iam-responder` runs on: an ECS service, an EKS deployment, or something
else). That root stack -- global bootstrap, state backend, networking,
the compute platform choice, secrets for `IAM_RESPONDER_API_KEY` -- is
real follow-up work, not built here.

The plan all along has been to mirror `demand-gig-engine`'s Terraform
structure and reuse its modules as-is (`kms`, `networking`, `security`,
`ecs_cluster`/`ecs_service`, `alb`, `cloudwatch`, `secrets_manager`,
`github_oidc`, and others) for that root stack, in a fresh AWS account
separate from every account Golem monitors. Nothing here does that
reuse yet -- these two modules are self-contained and don't depend on
anything from `demand-gig-engine`.

**No real cross-account trust exists yet.** These modules are correct
and tested against the AWS provider's own logic, but neither has been
applied to a real AWS account. `iam-responder`'s own test suite
acknowledges the same gap (moto simulates the AWS API surface; it isn't
a real account).

## Conventions

Matches `demand-gig-engine/terraform/modules/*`'s own conventions
exactly, since these are meant to sit alongside that project's patterns
once a root stack exists: `data "aws_iam_policy_document"` over raw JSON,
a `# Purpose:` header comment plus a why-comment on every resource/data
block, `variables.tf` validation blocks with explicit error messages,
pinned `versions.tf` (`aws ~> 6.57.1`), and a generated-looking
`README.md` per module (hand-written here, since this project doesn't
have `demand-gig-engine`'s doc-generation tooling).
