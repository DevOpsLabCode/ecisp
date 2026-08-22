# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Creates the dedicated S3 destination used by ALB and CloudTrail S3 server-access logging.
# Reading guide: The bucket is deliberately isolated from application data and retains immutable historical log versions.
# Vendored from demand-gig-engine/terraform/modules/access_logs with the CloudFront-specific canonical-user ACL grant
# removed -- Golem V1 has no CloudFront distribution to deliver legacy standard logs (see terraform/README.md), so
# that grant would exist for a service this module never talks to. Everything else (ALB delivery policy, encryption,
# versioning, lifecycle, public-access block, insecure-transport deny) is unchanged.

# Read the active AWS account so the ALB delivery policy can be scoped to this account only.
data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

resource "aws_s3_bucket" "this" {
  #checkov:skip=CKV_AWS_18:A dedicated terminal log sink cannot log to itself without recursively generating new access-log objects.
  #checkov:skip=CKV_AWS_144:Cross-region replication is delegated to a future organization backup and disaster-recovery policy, out of scope for the V1 self-sufficient stack.
  #checkov:skip=CKV2_AWS_62:Security analytics reads the centralized prefixes directly; per-object event notifications are not part of the control design.
  #checkov:skip=CKV_AWS_145:ALB access-log delivery requires S3-managed encryption compatibility; application and audit data use customer-managed KMS keys.
  bucket        = var.name
  force_destroy = var.force_destroy
  tags          = var.tags
}

resource "aws_s3_bucket_ownership_controls" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Reject all public ACL and bucket-policy exposure.
resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Preserve previous log-object versions for investigation and recovery.
resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Encrypt every delivered log object at rest with Amazon S3 managed keys.
resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Abort abandoned uploads and transition/expire old logs according to the retention policy.
resource "aws_s3_bucket_lifecycle_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    id     = "centralized-access-log-retention"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    transition {
      days          = 90
      storage_class = "GLACIER_IR"
    }

    expiration {
      days = var.retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = var.noncurrent_version_expiration_days
    }
  }
}

# Permit ALB log delivery to the account-scoped prefix and deny every non-TLS S3 request.
data "aws_iam_policy_document" "this" {
  statement {
    sid       = "AllowALBLogDelivery"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.this.arn}/${var.alb_prefix}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]

    principals {
      type        = "Service"
      identifiers = ["logdelivery.elasticloadbalancing.amazonaws.com"]
    }
  }

  statement {
    sid       = "AllowS3ServerAccessLogDelivery"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.this.arn}/s3/*"]

    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:${data.aws_partition.current.partition}:s3:::*"]
    }
  }

  statement {
    sid       = "AllowALBLogDeliveryAclCheck"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.this.arn]

    principals {
      type        = "Service"
      identifiers = ["logdelivery.elasticloadbalancing.amazonaws.com"]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.this.arn, "${aws_s3_bucket.this.arn}/*"]

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

resource "aws_s3_bucket_policy" "this" {
  bucket = aws_s3_bucket.this.id
  policy = data.aws_iam_policy_document.this.json
}
