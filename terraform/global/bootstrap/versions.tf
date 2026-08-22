# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Pins the remote-state bootstrap stack to the same tested Terraform and AWS provider family as the workload stack.

terraform {
  backend "s3" {}

  required_version = ">= 1.15.0, < 1.16.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.57.1"
    }
  }
}

provider "aws" {
  region = var.aws_region
}
