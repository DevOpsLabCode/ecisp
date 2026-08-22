# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Owns account/region singleton controls that must not be recreated by each environment stack.
# Adapted from demand-gig-engine/terraform/global/account -- see terraform/README.md's global/account scope decision.
# Golem includes this layer (GitHub OIDC + Terraform plan/apply roles + GuardDuty + enhanced ECR scanning) because the
# project clearly intends GitHub-based CI even though no workflow exists yet, and because GuardDuty/ECR scanning are
# cheap, valuable, account-wide security controls for a *security product*. What's dropped relative to the vendored
# original: the ElastiCache service-linked role and its narrowly scoped iam:PutRolePolicy statement (Golem has no
# ElastiCache/Redis workload -- see terraform/README.md's explicit out-of-scope list), and the
# "replication.ecr.amazonaws.com" service-linked-role allowance (Golem's root stack does not configure ECR
# cross-region replication).

locals {
  tags = merge(
    {
      Project   = var.project_name
      ManagedBy = "Terraform"
      Owner     = "DevOps Lab Inc."
      Scope     = "account-foundation"
    },
    var.tags,
  )
}

# Resolve GitHub's current certificate chain so the account-level IAM OIDC provider can validate Actions tokens.
data "tls_certificate" "github" {
  url = "https://token.actions.githubusercontent.com"
}

# GitHub's IAM OIDC provider is an account-wide singleton. Environment modules reference it rather than owning it.
resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.github.certificates[0].sha1_fingerprint]

  tags = local.tags
}

# GuardDuty supports one detector per account and region; this foundation stack is its sole lifecycle owner.
resource "aws_guardduty_detector" "this" {
  enable                       = true
  finding_publishing_frequency = var.guardduty_finding_frequency
  tags                         = local.tags
}

# In a delegated GuardDuty administrator account, enroll every existing and future
# AWS Organizations member in this region. Workload accounts leave this disabled
# because only the delegated administrator may manage organization configuration.
resource "aws_guardduty_organization_configuration" "this" {
  count                            = var.enable_guardduty_organization_auto_enrollment ? 1 : 0
  auto_enable_organization_members = "ALL"
  detector_id                      = aws_guardduty_detector.this.id
}

# Protect S3 activity with GuardDuty data-event analysis.
resource "aws_guardduty_detector_feature" "s3_data_events" {
  detector_id = aws_guardduty_detector.this.id
  name        = "S3_DATA_EVENTS"
  status      = "ENABLED"
}

# Enable GuardDuty malware scans for suspicious EBS volumes.
resource "aws_guardduty_detector_feature" "ebs_malware_protection" {
  detector_id = aws_guardduty_detector.this.id
  name        = "EBS_MALWARE_PROTECTION"
  status      = "ENABLED"
}

# Analyze supported RDS login activity for suspicious database authentication behavior.
resource "aws_guardduty_detector_feature" "rds_login_events" {
  detector_id = aws_guardduty_detector.this.id
  name        = "RDS_LOGIN_EVENTS"
  status      = "ENABLED"
}

# Enable runtime monitoring only when explicitly requested; Fargate agent management is tied to this feature.
resource "aws_guardduty_detector_feature" "runtime_monitoring" {
  count       = var.enable_guardduty_runtime_monitoring ? 1 : 0
  detector_id = aws_guardduty_detector.this.id
  name        = "RUNTIME_MONITORING"
  status      = "ENABLED"

  additional_configuration {
    name   = "ECS_FARGATE_AGENT_MANAGEMENT"
    status = "ENABLED"
  }
}

# Enhanced ECR scanning is account-wide and continuously evaluates pushed images through Amazon Inspector.
resource "aws_ecr_registry_scanning_configuration" "this" {
  count     = var.enable_enhanced_ecr_scanning ? 1 : 0
  scan_type = "ENHANCED"

  rule {
    scan_frequency = "CONTINUOUS_SCAN"

    repository_filter {
      filter      = "*"
      filter_type = "WILDCARD"
    }
  }
}

# Construct separate OIDC subject sets so pull requests can plan without receiving apply permissions.
locals {
  plan_subjects = concat(
    [for branch in var.plan_branches : "repo:${var.github_org}/${var.github_repo}:ref:refs/heads/${branch}"],
    var.allow_plan_pull_requests ? ["repo:${var.github_org}/${var.github_repo}:pull_request"] : [],
    [for environment in var.plan_environments : "repo:${var.github_org}/${var.github_repo}:environment:${environment}"],
  )
  apply_subjects = concat(
    [for branch in var.apply_branches : "repo:${var.github_org}/${var.github_repo}:ref:refs/heads/${branch}"],
    [for environment in var.apply_environments : "repo:${var.github_org}/${var.github_repo}:environment:${environment}"],
  )

  # Workload stacks may create roles only for the two explicitly supported
  # environments. This intentionally excludes both Terraform control-plane
  # roles so the apply role cannot rewrite its own trust or permissions.
  environment_role_arns = [
    "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/${var.project_name}-dev-*",
    "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/${var.project_name}-prod-*",
  ]

  # Every environment-created role is capped by an AWS-managed boundary that
  # excludes IAM administration. The apply role cannot remove this boundary.
  permissions_boundary_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/PowerUserAccess"

  # Only managed policies actually used by the workload modules may be
  # attached (modules/backup, modules/rds_postgres).
  approved_managed_policy_arns = [
    "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup",
    "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole",
  ]

  state_bucket_arns = [
    "arn:${data.aws_partition.current.partition}:s3:::${var.project_name}-account-${data.aws_caller_identity.current.account_id}-tfstate",
    "arn:${data.aws_partition.current.partition}:s3:::${var.project_name}-dev-${data.aws_caller_identity.current.account_id}-tfstate",
    "arn:${data.aws_partition.current.partition}:s3:::${var.project_name}-prod-${data.aws_caller_identity.current.account_id}-tfstate",
  ]

  state_kms_aliases = [
    "alias/${var.project_name}-account-tfstate",
    "alias/${var.project_name}-dev-tfstate",
    "alias/${var.project_name}-prod-tfstate",
  ]
}

data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}

# Amazon RDS requires this account-wide service-linked role before it can
# create and operate DB instances and RDS Proxy resources (modules/rds_postgres).
# Import an existing role into this state when necessary; otherwise this
# resource creates it before the environment deployment begins.
resource "aws_iam_service_linked_role" "rds" {
  aws_service_name = "rds.amazonaws.com"
  description      = "Allows Amazon RDS to manage required AWS resources."
}

# Shared trust-policy template with different subject sets for plan and apply roles.
data "aws_iam_policy_document" "terraform_plan_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = local.plan_subjects
    }
  }
}

data "aws_iam_policy_document" "terraform_apply_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = local.apply_subjects
    }
  }
}

# Pull-request plans receive AWS read access plus only the S3 lock-file writes required by Terraform's native state locking.
resource "aws_iam_role" "terraform_plan" {
  name                 = "${var.project_name}-terraform-plan"
  assume_role_policy   = data.aws_iam_policy_document.terraform_plan_assume.json
  max_session_duration = 3600
  tags                 = local.tags
}

resource "aws_iam_role_policy_attachment" "terraform_plan_readonly" {
  role       = aws_iam_role.terraform_plan.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/ReadOnlyAccess"
}

data "aws_iam_policy_document" "terraform_plan_state" {
  #checkov:skip=CKV_AWS_111:Write access is limited to Terraform native .tflock objects in three exact project/account state buckets.
  #checkov:skip=CKV_AWS_356:The only wildcard is an object-key suffix under exact project/account state bucket ARNs.
  statement {
    sid       = "ReadStateBuckets"
    actions   = ["s3:GetBucketLocation", "s3:ListBucket"]
    resources = local.state_bucket_arns
  }

  statement {
    sid     = "ReadStateObjects"
    actions = ["s3:GetObject"]
    resources = flatten([
      for arn in local.state_bucket_arns : ["${arn}/*"]
    ])
  }

  statement {
    sid     = "ManageNativeLockFiles"
    actions = ["s3:DeleteObject", "s3:GetObject", "s3:PutObject"]
    resources = flatten([
      for arn in local.state_bucket_arns : ["${arn}/*.tflock"]
    ])
  }

  # Terraform must decrypt state and encrypt its native S3 lock object. Key IDs
  # are bootstrap outputs, so the policy uses the exact approved aliases rather
  # than granting access to unrelated account keys.
  statement {
    sid = "UseTerraformStateKeys"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:GenerateDataKey",
    ]
    resources = ["*"]

    condition {
      test     = "ForAnyValue:StringEquals"
      variable = "kms:ResourceAliases"
      values   = local.state_kms_aliases
    }
  }
}

resource "aws_iam_role_policy" "terraform_plan_state" {
  name   = "${var.project_name}-terraform-plan-state"
  role   = aws_iam_role.terraform_plan.id
  policy = data.aws_iam_policy_document.terraform_plan_state.json
}

# Manual protected-environment deployments receive service-level PowerUser access, but not AdministratorAccess.
resource "aws_iam_role" "terraform_apply" {
  name                 = "${var.project_name}-terraform-apply"
  assume_role_policy   = data.aws_iam_policy_document.terraform_apply_assume.json
  max_session_duration = 3600
  tags                 = local.tags
}

resource "aws_iam_role_policy_attachment" "terraform_apply_power_user" {
  role       = aws_iam_role.terraform_apply.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/PowerUserAccess"
}

# PowerUserAccess excludes IAM. Add only bounded dev/prod role lifecycle, approved policy attachments, constrained PassRole, and required service-linked role creation.
data "aws_iam_policy_document" "terraform_apply_iam" {
  #checkov:skip=CKV_AWS_111:Mutable IAM operations are limited to exact dev/prod role prefixes and every created role must retain the approved permissions boundary.
  #checkov:skip=CKV_AWS_356:IAM list operations and CreateServiceLinkedRole require Resource "*"; the latter is constrained to an explicit service-name allowlist.
  statement {
    sid = "ManageBoundedEnvironmentRoles"
    actions = [
      "iam:DeleteRole",
      "iam:DeleteRolePolicy",
      "iam:GetRole",
      "iam:GetRolePolicy",
      "iam:ListAttachedRolePolicies",
      "iam:ListInstanceProfilesForRole",
      "iam:ListRolePolicies",
      "iam:ListRoleTags",
      "iam:PutRolePolicy",
      "iam:TagRole",
      "iam:UntagRole",
      "iam:UpdateAssumeRolePolicy",
      "iam:UpdateRole",
    ]
    resources = local.environment_role_arns
  }

  statement {
    sid       = "CreateBoundedEnvironmentRoles"
    actions   = ["iam:CreateRole"]
    resources = local.environment_role_arns

    condition {
      test     = "StringEquals"
      variable = "iam:PermissionsBoundary"
      values   = [local.permissions_boundary_arn]
    }
  }

  statement {
    sid       = "MaintainApprovedPermissionsBoundary"
    actions   = ["iam:PutRolePermissionsBoundary"]
    resources = local.environment_role_arns

    condition {
      test     = "StringEquals"
      variable = "iam:PermissionsBoundary"
      values   = [local.permissions_boundary_arn]
    }
  }

  statement {
    sid       = "AttachApprovedManagedPolicies"
    actions   = ["iam:AttachRolePolicy", "iam:DetachRolePolicy"]
    resources = local.environment_role_arns

    condition {
      test     = "ArnEquals"
      variable = "iam:PolicyARN"
      values   = local.approved_managed_policy_arns
    }
  }

  statement {
    sid       = "PassBoundedEnvironmentRolesToApprovedServices"
    actions   = ["iam:PassRole"]
    resources = local.environment_role_arns

    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values = [
        "backup.amazonaws.com",
        "cloudtrail.amazonaws.com",
        "ecs-tasks.amazonaws.com",
        "monitoring.rds.amazonaws.com",
        "vpc-flow-logs.amazonaws.com",
      ]
    }
  }

  statement {
    sid       = "ReadApprovedManagedPolicies"
    actions   = ["iam:GetPolicy", "iam:GetPolicyVersion", "iam:ListPolicyVersions"]
    resources = local.approved_managed_policy_arns
  }

  statement {
    sid       = "ListIAMMetadata"
    actions   = ["iam:ListPolicies", "iam:ListRoles"]
    resources = ["*"]
  }

  statement {
    sid       = "CreateApprovedServiceLinkedRoles"
    actions   = ["iam:CreateServiceLinkedRole"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "iam:AWSServiceName"
      values = [
        "autoscaling.amazonaws.com",
        "backup.amazonaws.com",
        "ecs.amazonaws.com",
        "elasticloadbalancing.amazonaws.com",
        "guardduty.amazonaws.com",
        "rds.amazonaws.com",
      ]
    }
  }
}

resource "aws_iam_role_policy" "terraform_apply_iam" {
  name   = "${var.project_name}-terraform-apply-iam"
  role   = aws_iam_role.terraform_apply.id
  policy = data.aws_iam_policy_document.terraform_apply_iam.json
}
