# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Creates the standalone IAM policy granting Golem's iam-responder execution identity permission to assume into any monitored account -- the other half of the Tier 4 cross-account trust relationship (see golem_monitored_account_trust, applied per monitored account).
# Reading guide: Each comment explains why the following Terraform block exists.

# A standalone managed policy, not a role -- this module doesn't know or
# assume how iam-responder is deployed (ECS task role, EKS pod IRSA role,
# a plain IAM user for a first trial run, ...). The composition that
# deploys iam-responder attaches this policy's ARN to whatever execution
# role it creates for that compute platform.
data "aws_iam_policy_document" "assume_monitored_accounts" {
  statement {
    sid       = "AssumeGolemMonitoredAccountRole"
    actions   = ["sts:AssumeRole"]
    resources = ["arn:*:iam::*:role/${var.monitored_role_name}"]
  }
}

resource "aws_iam_policy" "assume_monitored_accounts" {
  name   = var.name
  policy = data.aws_iam_policy_document.assume_monitored_accounts.json
  tags   = var.tags
}
