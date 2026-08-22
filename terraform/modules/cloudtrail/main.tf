# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Creates encrypted multi-region CloudTrail auditing, lifecycle-controlled storage, access logging, and encrypted SNS notifications.
# Vendored from demand-gig-engine/terraform/modules/cloudtrail with no logic changes -- see terraform/README.md for the vendoring rationale.

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  trail_arn   = "arn:${data.aws_partition.current.partition}:cloudtrail:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:trail/${var.name}"
  account_arn = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
}

resource "aws_s3_bucket" "logs" {
  #checkov:skip=CKV_AWS_144:Cross-region replication is a future organization-level immutable audit archive, out of scope for the V1 self-sufficient stack.
  #checkov:skip=CKV2_AWS_62:CloudTrail already emits encrypted SNS delivery notifications; duplicate per-object S3 notifications add cost without an authorization boundary.
  bucket = "${var.name}-${data.aws_caller_identity.current.account_id}-cloudtrail"
  tags   = var.tags
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }

    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_logging" "logs" {
  bucket        = aws_s3_bucket.logs.id
  target_bucket = var.access_log_bucket_id
  target_prefix = "s3/cloudtrail/"
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    id     = "archive"
    status = "Enabled"
    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    # S3 requires expiration to occur after every storage-class transition.
    # Development retention can be 90 days or less, so omit the transition in
    # those environments rather than submitting an invalid lifecycle rule.
    dynamic "transition" {
      for_each = var.retention_days > 90 ? [1] : []

      content {
        days          = 90
        storage_class = "GLACIER_IR"
      }
    }

    expiration {
      days = var.retention_days
    }
  }
}

data "aws_iam_policy_document" "logs" {
  statement {
    sid       = "AWSCloudTrailAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.logs.arn]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid       = "AWSCloudTrailWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.logs.arn, "${aws_s3_bucket.logs.arn}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "logs" {
  bucket = aws_s3_bucket.logs.id
  policy = data.aws_iam_policy_document.logs.json
}

resource "aws_sns_topic" "notifications" {
  name              = "${var.name}-cloudtrail"
  kms_master_key_id = var.kms_key_arn
  tags              = var.tags
}

data "aws_iam_policy_document" "notifications" {
  statement {
    sid       = "AllowCloudTrailPublish"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.notifications.arn]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid       = "AllowAccountAdministration"
    effect    = "Allow"
    actions   = ["sns:GetTopicAttributes", "sns:SetTopicAttributes", "sns:Subscribe"]
    resources = [aws_sns_topic.notifications.arn]

    principals {
      type        = "AWS"
      identifiers = [local.account_arn]
    }
  }

  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"
    # SNS topic resource policies accept only the documented topic actions;
    # the wildcard action is rejected by SetTopicAttributes.
    actions = [
      "sns:AddPermission",
      "sns:DeleteTopic",
      "sns:GetDataProtectionPolicy",
      "sns:GetTopicAttributes",
      "sns:ListSubscriptionsByTopic",
      "sns:ListTagsForResource",
      "sns:Publish",
      "sns:PutDataProtectionPolicy",
      "sns:RemovePermission",
      "sns:SetTopicAttributes",
      "sns:Subscribe",
    ]
    resources = [aws_sns_topic.notifications.arn]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_sns_topic_policy" "notifications" {
  arn    = aws_sns_topic.notifications.arn
  policy = data.aws_iam_policy_document.notifications.json
}


resource "aws_cloudwatch_log_group" "trail" {
  name              = "/aws/cloudtrail/${var.name}"
  retention_in_days = 365
  kms_key_id        = var.kms_key_arn
  tags              = var.tags
}

data "aws_iam_policy_document" "cloudtrail_logs_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "cloudtrail_logs" {
  permissions_boundary = var.permissions_boundary_arn
  name                 = "${var.name}-cloudtrail-logs"
  assume_role_policy   = data.aws_iam_policy_document.cloudtrail_logs_assume.json
  tags                 = var.tags
}

data "aws_iam_policy_document" "cloudtrail_logs" {
  statement {
    sid       = "WriteCloudTrailEvents"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.trail.arn}:*"]
  }
}

resource "aws_iam_role_policy" "cloudtrail_logs" {
  name   = "${var.name}-cloudtrail-logs"
  role   = aws_iam_role.cloudtrail_logs.id
  policy = data.aws_iam_policy_document.cloudtrail_logs.json
}

resource "aws_cloudtrail" "this" {
  name                          = var.name
  s3_bucket_name                = aws_s3_bucket.logs.id
  sns_topic_name                = aws_sns_topic.notifications.name
  kms_key_id                    = var.kms_key_arn
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.trail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_logs.arn

  # Management events are always captured. Production can additionally capture object-level access for selected S3 buckets.
  event_selector {
    read_write_type           = "All"
    include_management_events = true

    dynamic "data_resource" {
      for_each = length(var.s3_data_event_bucket_arns) == 0 ? [] : [1]

      content {
        type   = "AWS::S3::Object"
        values = [for arn in var.s3_data_event_bucket_arns : "${arn}/"]
      }
    }
  }

  # CloudTrail Insights identifies unusual API call and API error rates. It is configurable because Insights creates additional billable events.
  dynamic "insight_selector" {
    for_each = var.enable_insights ? toset(["ApiCallRateInsight", "ApiErrorRateInsight"]) : toset([])

    content {
      insight_type = insight_selector.value
    }
  }

  depends_on = [
    aws_s3_bucket_policy.logs,
    aws_sns_topic_policy.notifications,
    aws_iam_role_policy.cloudtrail_logs,
  ]

  tags = var.tags
}
