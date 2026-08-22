# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Configures the AWS provider connection used by every resource and module in this root stack.
# Reading guide: Each comment explains why the following block exists.
# Golem V1 has no CloudFront distribution and therefore no us-east-1-only ACM/WAF requirement (see terraform/README.md
# and modules/alb's README) -- unlike demand-gig-engine's root, this provider block needs no us-east-1 alias.

# Configure the AWS provider connection used by every resource and module below.
provider "aws" {
  region = var.aws_region
  default_tags {
    tags = merge(var.tags, {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "Terraform"
      Owner       = "DevOps Lab Inc."
      Repository  = "${var.github_org}/${var.github_repo}"
    })
  }
}

# Read the active AWS account ID so names, policies, and diagnostics match the credentials running Terraform.
data "aws_caller_identity" "current" {}
# Read the active AWS partition so account and service ARNs remain portable.
data "aws_partition" "current" {}
