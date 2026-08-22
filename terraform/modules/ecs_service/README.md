# `ecs_service` Terraform module

> **Author:** Stan Zvenigorodskiy
> **Organization:** DevOps Lab Inc.
> **Website:** [DevOpsLabInc.com](https://DevOpsLabInc.com)

## Purpose

Creates a complete Fargate service: task-execution and application task IAM
roles, an application container definition (health check, structured
logging, dropped Linux capabilities, read-only root filesystem), an
optional AWS X-Ray sidecar, the ECS service itself, and optional CPU/memory
target-tracking autoscaling. Vendored from
`demand-gig-engine/terraform/modules/ecs_service` with **no logic
changes**.

## How Golem uses this module

Golem's root stack (`terraform/main.tf`) instantiates this module twice:

- **`golem-backend`** -- `expose_port = true`, a `target_group_arn` from
  `modules/alb`, environment/secrets wiring the RDS Proxy endpoint and
  `DATABASE_URL` secret from `modules/rds_postgres`.
- **`golem-iam-responder`** -- `expose_port = false` (it is a polling loop
  with no HTTP server, per `iam-responder/app/__main__.py`), no
  `target_group_arn`, `enable_health_check = false`, and the
  `golem_iam_responder_execution` module's policy attached separately to
  its `task_role_arn` output via `aws_iam_role_policy_attachment` (this
  module intentionally does not know about cross-account trust policies).

Neither service uses this module's SQS, S3, SES, or X-Ray integrations in
Golem V1 (see `terraform/README.md`'s out-of-scope list) -- both call
sites pass `queue_arn = ""` with `queue_actions = []`,
`object_storage_bucket_arn = null`, `ses_identity_arn = null`, and
`enable_xray = false` rather than a stripped-down copy of this module,
since keeping the full module lets a later Golem feature turn any of these
on without a rewrite.

## Inputs

See `variables.tf` -- every input has a validation block with an explicit
error message. The notable ones for Golem's call sites: `image` (ECR URI
with an explicit tag, supplied by CI, not Terraform), `queue_arn` /
`queue_actions` (leave `queue_actions = []` to opt out, per above),
`expose_port` / `target_group_arn` (a worker-style service like
`golem-iam-responder` sets `expose_port = false` and omits
`target_group_arn`), `permissions_boundary_arn` (wired from root's
`locals.permissions_boundary_arn`).

## Outputs

| Name | Description |
|---|---|
| `service_name` | ECS service name. |
| `service_arn` | ECS service ARN. |
| `task_role_arn` | Application task role ARN -- Golem's root stack attaches `golem_iam_responder_execution`'s policy here for `golem-iam-responder`. |
| `task_definition_arn` | Task definition ARN. |

## Testing

```bash
terraform init -backend=false
terraform test
```

Runs entirely offline against a credential-free provider configuration.
