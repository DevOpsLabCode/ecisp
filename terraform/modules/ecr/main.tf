# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Creates immutable, encrypted container repositories with lifecycle cleanup and vulnerability scanning.
# Reading guide: Each comment explains why the following Terraform block exists.
# Vendored from demand-gig-engine/terraform/modules/ecr with no logic changes -- see terraform/README.md for the
# vendoring rationale. Golem's root stack instantiates this once with repositories = ["backend", "iam-responder"].

# Create and manage the AWS ECR repositories owned by this module.
resource "aws_ecr_repository" "this" {
  for_each = var.repositories

  name                 = "${var.name}-${each.key}"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = var.force_delete

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = var.kms_key_arn
  }

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = var.tags
}

# Remove superseded images while retaining a safe rollback window.
#
# Iterate over var.repositories because its keys are known during terraform plan.
# The repository name can safely reference the corresponding ECR resource value.
resource "aws_ecr_lifecycle_policy" "this" {
  for_each = var.repositories

  repository = aws_ecr_repository.this[each.key].name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep the configured rollback image window"

        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = var.retained_image_count
        }

        action = {
          type = "expire"
        }
      }
    ]
  })
}
