# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Pins the Terraform CLI and provider versions supported by this reusable child module.

terraform {
  required_version = ">= 1.15.0, < 1.16.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.57.1"
    }
  }
}
