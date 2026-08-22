# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Pins Terraform and provider compatibility ranges to tested stable releases.

terraform {
  backend "s3" {}

  required_version = ">= 1.15.0, < 1.16.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.57.1"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.7"
    }
  }
}
