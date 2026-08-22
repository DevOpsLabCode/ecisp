# Golem Terraform

## What's here

A complete, self-sufficient Terraform root stack that stands up the whole
Golem Defender platform in a brand-new, empty AWS account: networking,
the backend API, its Postgres database, the `iam-responder` service, IAM,
secrets, container registry, observability, backup, and audit logging --
nothing else required beyond an AWS account and (optionally) a domain.
This replaces the "No root stack" gap this file used to describe.

### Root stack (`terraform/`)

`main.tf` composes every module below into one environment (`dev` or
`prod`, selected by `envs/<environment>/terraform.tfvars`). See
`envs/dev/terraform.tfvars` for a genuinely minimal, cheap-to-run
configuration and `envs/prod/terraform.tfvars` for a production-shaped
one (structural completeness only -- neither has been applied to a real
account, see "What remains unverified" below).

### Global layers (`terraform/global/`)

- **`global/bootstrap`** -- the protected S3 state backend (KMS-encrypted,
  versioned, `prevent_destroy`, **S3-native locking** via
  `use_lockfile = true`, a Terraform >= 1.10 feature -- no DynamoDB lock
  table) plus its own access-log bucket. Applied once per environment
  scope (`account`, `dev`, `prod`) before that scope's own root can use an
  S3 backend at all -- see `scripts/bootstrap.sh`.
- **`global/account`** -- account/region singletons: GitHub Actions OIDC
  provider, bounded Terraform plan/apply roles, GuardDuty detector and
  features, optional enhanced ECR scanning. See "Decision 2" below for
  why this exists in V1.

### Reusable child modules (`terraform/modules/`)

Vendored as-is from `demand-gig-engine/terraform/modules/*` (no
architectural changes, only Golem-specific naming/defaults where noted):
`kms`, `networking`, `ecs_cluster`, `ecs_service`, `rds_postgres`,
`secrets_manager`, `ecr`, `backup`, `cloudtrail`, `access_logs`.

Adapted for Golem's V1 constraints (no CloudFront, no Redis, no SQS -- see
"Out of scope" below), each documented in its own README:

- **`security`** -- plain internet ingress on the ALB security group
  instead of the CloudFront origin-facing managed prefix list; no `redis`
  security group.
- **`alb`** -- the no-certificate branch forwards HTTP directly and
  unconditionally instead of gating it behind a CloudFront-only header.
  See "Decision 1" below.
- **`cloudwatch`** -- drops every Redis/SQS/CloudFront alarm and dashboard
  widget; ALB/ECS/RDS alarms and the dashboard structure are unchanged.

Golem-specific, not from `demand-gig-engine` at all:

- **`golem_monitored_account_trust`** -- applied once per AWS account
  Golem monitors, by that account's own operators. Creates the role
  `iam-responder` assumes into that account for Tier 4 (`revoke_iam`)
  responses. **Not called by this root stack** -- see its own README.
- **`golem_iam_responder_execution`** -- applied by this root stack.
  Creates the policy letting `golem-iam-responder`'s own ECS task role
  assume into any monitored account's trust role.

Every module is independently tested (`terraform test`, entirely
offline) and validated against a real Terraform CLI (`terraform fmt`,
`terraform validate`).

## Three decisions this root stack embodies

### Decision 1: ALB certificate / no-CloudFront-in-front

Golem V1 has no CDN (see "Out of scope" below). `demand-gig-engine`'s
`alb` module's no-certificate branch gates HTTP forwarding behind an
`X-Origin-Verify` header only CloudFront would ever send -- reused
unmodified, that would make Golem's ALB permanently unreachable by
design. Two options existed: (a) always require a real ACM
`certificate_arn` (HTTPS-only, no domain = no deploy), or (b) make
`certificate_arn` optional and give Golem's own copy of the module a
different, unconditional-forward no-certificate branch.

**Chose (b).** `var.certificate_arn` defaults to `null`; with no
certificate configured, the ALB serves plain HTTP on its own
AWS-generated hostname, unauthenticated at the transport layer -- an
accepted, documented trade-off for a quick trial or an
internal/VPN-only rollout, not for production traffic carrying sensitive
data. Configure `certificate_arn` (a regional ACM certificate, issued and
DNS-validated **outside this stack** -- Route 53 automation is explicitly
out of scope, see below) and `domain_name` (purely informational, used
only to compute `application_url`) once you own a domain and have pointed
its DNS at the output `alb_dns_name`. See `modules/alb/README.md` for the
full reasoning.

### Decision 2: `global/account` scope

`demand-gig-engine` treats GitHub OIDC + Terraform CI roles + GuardDuty +
ECR scanning as foundational, account-wide infrastructure. Golem's V1
scope could reasonably have omitted all of it (no CI workflow exists in
this repository yet). The safe default -- and what's actually built here
-- is to **include** a minimal `global/account` layer anyway: the project
clearly intends GitHub-based CI eventually, and GuardDuty/enhanced ECR
scanning are cheap, valuable, account-wide security controls that are
particularly apt for a security product to enable in its own account from
day one. Two things present in `demand-gig-engine`'s version are dropped
because Golem has no matching workload: the ElastiCache service-linked
role, and the `replication.ecr.amazonaws.com` service-linked-role
allowance. See `global/account/README.md`.

### Decision 3: Backup Vault Lock default

`modules/backup` supports AWS Backup Compliance-mode Vault Lock, which
fits Golem's own containment build plan's "immutable backups" theme
conceptually. It is also **irreversible once its grace period elapses**
-- nothing, including AWS, can shorten retention or delete the vault
before recovery points expire. `enable_backup_vault_lock` defaults to
`false` everywhere (both `envs/dev` and `envs/prod` tfvars) so a
first-time deploy to a brand-new account can't have its first mistake
become permanent. Enable it deliberately, per environment, only after
validating retention requirements. See `modules/backup/README.md`.

## Out of scope for V1 (by design, not by omission)

`redis`, `sqs`, `eventbridge`, `ses`, `route53`, `s3_static` (no frontend
hosting in this root stack), `waf`, `cloudfront`/`acm` (see Decision 1),
and a separate `xray` module (the `ecs_service` module's X-Ray sidecar
toggle stays available since it's part of the vendored module; both
Golem call sites simply leave `enable_xray = false`). None of these are
silently missing -- each is a deliberate exclusion, documented here and,
where it changes a vendored module's behavior, in that module's own
README.

## What remains unverified without real AWS credentials

Every module and the root composition have been verified **offline**:
`terraform fmt -recursive`, `terraform init -backend=false`, `terraform
validate`, `terraform test` (real `.tftest.hcl` suites with meaningful
assertions, not smoke tests), and a full-tree `checkov` scan (552 checks
passed, 0 failed, 34 documented `#checkov:skip` comments as of this
writing). That is genuinely strong evidence the Terraform is internally
consistent, type-correct, and free of the security misconfigurations
Checkov's ruleset covers.

**None of it has been applied to a real AWS account.** `terraform plan`
and `terraform apply` both require real AWS credentials and make real API
calls -- neither was attempted, per this work's explicit instructions.
Concretely, still unverified:

- Whether `scripts/bootstrap.sh`'s local-state-then-migrate dance actually
  works end-to-end against a fresh account (it has been read and reasoned
  through carefully, adapted line-for-line from a script that has run
  successfully in `demand-gig-engine`, but never executed here).
- Whether every module composes into a plan AWS actually accepts --
  `terraform validate` catches type/reference errors, not AWS API-level
  rejections (quota limits, IAM policy size limits, region-specific
  service availability, RDS engine-version validity, etc.).
- Whether the two ECS services actually come up healthy against real
  container images (none exist yet -- `backend_image`/`iam_responder_image`
  are placeholder `"REPLACED_BY_CI"` values in both tfvars files).
- Whether `golem-iam-responder`'s `BACKEND_URL` (the ALB's own hostname)
  is actually reachable from inside the VPC's private app subnets the way
  this composition assumes.
- Cost and quota behavior at real AWS scale.

Treat this as thoroughly-reasoned, statically-verified Terraform ready
for a first trial apply with real credentials in a disposable account --
not as infrastructure that has been proven to work.

## Conventions

Matches `demand-gig-engine/terraform/modules/*`'s own conventions
exactly: `data "aws_iam_policy_document"` over raw JSON, a `# Purpose:`
header comment plus a why-comment on every resource/data block,
`variables.tf` validation blocks with explicit error messages, pinned
`versions.tf` (`aws ~> 6.57.1`), and a hand-written `README.md` per
module (this project doesn't have `demand-gig-engine`'s doc-generation
tooling).
