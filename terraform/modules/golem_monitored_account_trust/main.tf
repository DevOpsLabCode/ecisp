# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Grants Golem's iam-responder a narrowly-trusted, narrowly-permissioned role in a monitored AWS account -- the Tier 4 half of the containment build plan's privilege-separated IAM revocation. Applied once per monitored account, by that account's own operators.
# Reading guide: Each comment explains why the following Terraform block exists.

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

# Build the trust policy: only var.trusted_principal_arn (iam-responder's
# own execution role, never an account root) may assume this role, and
# only when it presents the configured external ID -- the standard AWS
# mitigation for the confused-deputy problem inherent to any third-party
# cross-account role assumption (see the README).
data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [var.trusted_principal_arn]
    }

    dynamic "condition" {
      for_each = var.external_id != "" ? [var.external_id] : []
      content {
        test     = "StringEquals"
        variable = "sts:ExternalId"
        values   = [condition.value]
      }
    }
  }
}

# Build the permission policy: PutRolePolicy/DeleteRolePolicy scoped to
# this account's own golem-monitored-* roles only -- the actual
# revoke/release mechanism iam-responder's aws_actions.py calls -- plus
# one read with no meaningful resource to scope, used solely by the
# coverage sweep to confirm the assumed session can call IAM at all.
data "aws_iam_policy_document" "permissions" {
  statement {
    sid       = "RevokeMonitoredWorkloadRoles"
    actions   = ["iam:PutRolePolicy", "iam:DeleteRolePolicy"]
    resources = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/${var.monitored_role_name_prefix}*"]
  }

  statement {
    sid       = "CoverageSweepConnectivityCheck"
    actions   = ["iam:ListAccountAliases"]
    resources = ["*"]
  }
}

# Creates the role Golem's iam-responder assumes into this account.
resource "aws_iam_role" "golem_iam_responder" {
  name                  = var.role_name
  assume_role_policy    = data.aws_iam_policy_document.assume.json
  permissions_boundary  = var.permissions_boundary_arn
  max_session_duration  = 3600
  force_detach_policies = true
  tags                  = var.tags
}

resource "aws_iam_role_policy" "golem_iam_responder" {
  name   = "${var.role_name}-permissions"
  role   = aws_iam_role.golem_iam_responder.id
  policy = data.aws_iam_policy_document.permissions.json
}

# Surfaces a non-blocking warning (not a hard failure -- see Terraform's
# own `check` semantics) when no external ID is configured, since an
# empty external_id is a valid, deliberate choice for a low-risk trial
# setup, not something this module should refuse to apply over.
check "external_id_recommended" {
  assert {
    condition     = var.external_id != ""
    error_message = "external_id is unset -- recommended for any third-party cross-account role assumption (see the README's confused-deputy note). Not required, but consider setting one before production use."
  }
}
