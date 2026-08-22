# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Publishes reusable values produced by the golem_monitored_account_trust Terraform module.
# Reading guide: Each comment explains why the following Terraform block exists.

# Output `role_arn`: the exact ARN Golem's iam-responder assumes into
# this account -- register this with Golem via POST /api/aws-accounts
# (this account's account_id) so the coverage sweep starts tracking it.
output "role_arn" {
  description = "ARN of the role Golem's iam-responder assumes into this account."
  value       = aws_iam_role.golem_iam_responder.arn
}

# Output `role_name`: the bare role name, useful when composing the
# arn:aws:iam::{account_id}:role/{role_name} template iam-responder's own
# GOLEM_ASSUME_ROLE_TEMPLATE env var expects.
output "role_name" {
  description = "Name of the role Golem's iam-responder assumes into this account."
  value       = aws_iam_role.golem_iam_responder.name
}
