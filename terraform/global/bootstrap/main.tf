# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Creates independently secured remote-state storage and its terminal access-log sink before the main stack exists.
# Vendored from demand-gig-engine/terraform/global/bootstrap with no logic changes -- see terraform/README.md for the
# vendoring rationale. This is the very first thing applied to a brand-new AWS account: the state bucket the root
# stack's own `terraform{ backend "s3" {} }` block (versions.tf) depends on doesn't exist until this runs, so this
# root necessarily bootstraps itself with local state first -- see scripts/bootstrap.sh for the exact local-state-
# then-migrate dance, adapted from demand-gig-engine/scripts/bootstrap.sh.

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

data "aws_iam_policy_document" "state_kms" {
  #checkov:skip=CKV_AWS_109:KMS bootstrap key-policy Resource "*" denotes only this attached state key and administration is limited to the exact owning-account root principal.
  #checkov:skip=CKV_AWS_111:KMS key creation requires Resource "*" in the attached key policy; the only principal is the exact owning-account root identity.
  #checkov:skip=CKV_AWS_356:The bootstrap key ARN does not exist while its policy is evaluated, so AWS requires Resource "*" to identify this key only.
  statement {
    sid       = "EnableAccountAdministration"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }
}

resource "aws_kms_key" "state" {
  description             = "${var.project_name}-${var.environment} Terraform state encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.state_kms.json
}

resource "aws_kms_alias" "state" {
  name          = "alias/${var.project_name}-${var.environment}-tfstate"
  target_key_id = aws_kms_key.state.key_id
}

resource "aws_s3_bucket" "logs" {
  #checkov:skip=CKV_AWS_18:A terminal S3 access-log sink cannot log to itself without recursively generating new log objects.
  #checkov:skip=CKV_AWS_144:Cross-region replication is a future organization disaster-recovery account, intentionally outside bootstrap for V1.
  #checkov:skip=CKV2_AWS_62:Bootstrap logs are consumed by scheduled security analytics; per-object notification fan-out is not required.
  #checkov:skip=CKV_AWS_145:S3 server-access-log delivery uses S3-managed encryption for destination compatibility; Terraform state itself uses the customer-managed key.
  bucket = "${var.project_name}-${var.environment}-${data.aws_caller_identity.current.account_id}-tfstate-logs"
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
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    id     = "bootstrap-log-retention"
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
      days = 2555
    }

    noncurrent_version_expiration {
      noncurrent_days = 365
    }
  }
}

data "aws_iam_policy_document" "logs" {
  statement {
    sid       = "AllowS3ServerAccessLogDelivery"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs.arn}/s3/tfstate/*"]

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
      values   = [aws_s3_bucket.state.arn]
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

resource "aws_s3_bucket" "state" {
  #checkov:skip=CKV_AWS_144:State replication is owned by a future organization disaster-recovery account so bootstrap never requires cross-account credentials.
  #checkov:skip=CKV2_AWS_62:Terraform state changes are monitored through CloudTrail and CI; per-object S3 notifications are not an authorization boundary.
  bucket = "${var.project_name}-${var.environment}-${data.aws_caller_identity.current.account_id}-tfstate"

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_ownership_controls" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket                  = aws_s3_bucket.state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    bucket_key_enabled = true

    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.state.arn
    }
  }
}

resource "aws_s3_bucket_logging" "state" {
  bucket        = aws_s3_bucket.state.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "s3/tfstate/"

  depends_on = [aws_s3_bucket_policy.logs]
}

resource "aws_s3_bucket_lifecycle_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    id     = "state-version-retention"
    status = "Enabled"
    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    noncurrent_version_expiration {
      noncurrent_days = 2555
    }
  }
}

data "aws_iam_policy_document" "state" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.state.arn, "${aws_s3_bucket.state.arn}/*"]

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

resource "aws_s3_bucket_policy" "state" {
  bucket = aws_s3_bucket.state.id
  policy = data.aws_iam_policy_document.state.json
}

output "bucket" {
  description = "Name of the remote-state S3 bucket -- Terraform's own state backend for envs/<environment>, native S3 locking (use_lockfile = true, no DynamoDB)."
  value       = aws_s3_bucket.state.id
}

output "kms_key_arn" {
  description = "Customer-managed KMS key used by remote state."
  value       = aws_kms_key.state.arn
}
