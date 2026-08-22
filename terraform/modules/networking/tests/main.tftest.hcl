# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Verifies subnet counts, NAT gateway placement, and validation logic this module produces, entirely offline -- data.aws_availability_zones is overridden with a fixed AZ list so no real AWS API call is needed.

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_region_validation      = true
}

override_data {
  target = data.aws_availability_zones.available
  values = {
    names = ["us-east-1a", "us-east-1b", "us-east-1c"]
  }
}

run "creates_two_azs_worth_of_subnets_by_default" {
  command = plan

  variables {
    name                     = "golem-dev"
    cidr                     = "10.20.0.0/16"
    az_count                 = 2
    kms_key_arn              = "arn:aws:kms:us-east-1:111111111111:key/abcd1234-0000-0000-0000-000000000000"
    permissions_boundary_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
  }

  assert {
    condition     = length(aws_subnet.public) == 2
    error_message = "expected 2 public subnets for az_count=2"
  }

  assert {
    condition     = length(aws_subnet.app) == 2
    error_message = "expected 2 app subnets for az_count=2"
  }

  assert {
    condition     = length(aws_subnet.db) == 2
    error_message = "expected 2 db subnets for az_count=2"
  }
}

run "single_shared_nat_gateway_by_default" {
  command = plan

  variables {
    name                     = "golem-dev"
    cidr                     = "10.20.0.0/16"
    az_count                 = 2
    kms_key_arn              = "arn:aws:kms:us-east-1:111111111111:key/abcd1234-0000-0000-0000-000000000000"
    permissions_boundary_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
  }

  assert {
    condition     = length(aws_nat_gateway.this) == 1
    error_message = "nat_gateway_per_az=false should create exactly one shared NAT gateway"
  }
}

run "nat_gateway_per_az_creates_one_per_zone" {
  command = plan

  variables {
    name                     = "golem-dev"
    cidr                     = "10.20.0.0/16"
    az_count                 = 3
    nat_gateway_per_az       = true
    kms_key_arn              = "arn:aws:kms:us-east-1:111111111111:key/abcd1234-0000-0000-0000-000000000000"
    permissions_boundary_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
  }

  assert {
    condition     = length(aws_nat_gateway.this) == 3
    error_message = "nat_gateway_per_az=true with az_count=3 should create three NAT gateways"
  }
}

run "flow_log_group_uses_the_supplied_kms_key" {
  command = plan

  variables {
    name                     = "golem-dev"
    cidr                     = "10.20.0.0/16"
    az_count                 = 2
    kms_key_arn              = "arn:aws:kms:us-east-1:111111111111:key/abcd1234-0000-0000-0000-000000000000"
    permissions_boundary_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
  }

  assert {
    condition     = aws_cloudwatch_log_group.flow.kms_key_id == "arn:aws:kms:us-east-1:111111111111:key/abcd1234-0000-0000-0000-000000000000"
    error_message = "VPC flow-log group must be encrypted with the supplied KMS key"
  }

  assert {
    condition     = aws_cloudwatch_log_group.flow.name == "/aws/vpc/golem-dev/flow-logs"
    error_message = "flow-log group name should be /aws/vpc/<name>/flow-logs"
  }
}

run "rejects_a_cidr_smaller_than_slash_20" {
  command = plan

  variables {
    name                     = "golem-dev"
    cidr                     = "10.20.0.0/24"
    az_count                 = 2
    kms_key_arn              = "arn:aws:kms:us-east-1:111111111111:key/abcd1234-0000-0000-0000-000000000000"
    permissions_boundary_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
  }

  expect_failures = [var.cidr]
}

run "rejects_an_az_count_outside_two_or_three" {
  command = plan

  variables {
    name                     = "golem-dev"
    cidr                     = "10.20.0.0/16"
    az_count                 = 5
    kms_key_arn              = "arn:aws:kms:us-east-1:111111111111:key/abcd1234-0000-0000-0000-000000000000"
    permissions_boundary_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
  }

  expect_failures = [var.az_count]
}
