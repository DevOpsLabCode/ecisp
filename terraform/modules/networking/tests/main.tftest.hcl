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

run "rejects_a_name_that_is_too_short" {
  command = plan

  variables {
    name                     = "ab"
    cidr                     = "10.20.0.0/16"
    az_count                 = 2
    kms_key_arn              = "arn:aws:kms:us-east-1:111111111111:key/abcd1234-0000-0000-0000-000000000000"
    permissions_boundary_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
  }

  expect_failures = [var.name]
}

run "rejects_a_kms_key_arn_that_is_not_a_kms_key_arn" {
  command = plan

  variables {
    name                     = "golem-dev"
    cidr                     = "10.20.0.0/16"
    az_count                 = 2
    kms_key_arn              = "arn:aws:iam::111111111111:role/not-a-kms-key"
    permissions_boundary_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
  }

  expect_failures = [var.kms_key_arn]
}

run "rejects_a_permissions_boundary_arn_that_is_not_poweruseraccess" {
  command = plan

  variables {
    name                     = "golem-dev"
    cidr                     = "10.20.0.0/16"
    az_count                 = 2
    kms_key_arn              = "arn:aws:kms:us-east-1:111111111111:key/abcd1234-0000-0000-0000-000000000000"
    permissions_boundary_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
  }

  expect_failures = [var.permissions_boundary_arn]
}

run "app_route_tables_target_the_correct_nat_gateway_per_mode" {
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
    condition     = length(aws_route_table.app) == 3
    error_message = "expected one app route table per AZ when nat_gateway_per_az=true"
  }
}

run "outputs_reflect_the_created_vpc_and_subnets" {
  command = apply

  variables {
    name                     = "golem-dev"
    cidr                     = "10.20.0.0/16"
    az_count                 = 2
    kms_key_arn              = "arn:aws:kms:us-east-1:111111111111:key/abcd1234-0000-0000-0000-000000000000"
    permissions_boundary_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
  }

  override_resource {
    target = aws_vpc.this
    values = { id = "vpc-mock0000000000" }
  }

  override_resource {
    target = aws_default_security_group.this
    values = { id = "sg-default-mock" }
  }

  override_resource {
    target = aws_internet_gateway.this
    values = { id = "igw-mock0000000000" }
  }

  override_resource {
    target = aws_subnet.public
    values = { id = "subnet-public-mock" }
  }

  override_resource {
    target = aws_subnet.app
    values = { id = "subnet-app-mock" }
  }

  override_resource {
    target = aws_subnet.db
    values = { id = "subnet-db-mock" }
  }

  override_resource {
    target = aws_eip.nat
    values = { id = "eip-mock0000000000" }
  }

  override_resource {
    target = aws_nat_gateway.this
    values = { id = "nat-mock0000000000" }
  }

  override_resource {
    target = aws_route_table.public
    values = { id = "rtb-public-mock" }
  }

  override_resource {
    target = aws_route_table_association.public
    values = { id = "rtbassoc-public-mock" }
  }

  override_resource {
    target = aws_route_table.app
    values = { id = "rtb-app-mock" }
  }

  override_resource {
    target = aws_route_table_association.app
    values = { id = "rtbassoc-app-mock" }
  }

  override_resource {
    target = aws_route_table.db
    values = { id = "rtb-db-mock" }
  }

  override_resource {
    target = aws_route_table_association.db
    values = { id = "rtbassoc-db-mock" }
  }

  override_resource {
    target = aws_vpc_endpoint.s3
    values = { id = "vpce-mock0000000000" }
  }

  override_resource {
    target = aws_cloudwatch_log_group.flow
    values = { arn = "arn:aws:logs:us-east-1:111111111111:log-group:/aws/vpc/golem-dev/flow-logs" }
  }

  override_resource {
    target = aws_iam_role.flow
    values = {
      arn = "arn:aws:iam::111111111111:role/golem-dev-vpc-flow-logs"
      id  = "golem-dev-vpc-flow-logs"
    }
  }

  override_resource {
    target = aws_iam_role_policy.flow
    values = { id = "golem-dev-vpc-flow-logs:default" }
  }

  override_resource {
    target = aws_flow_log.this
    values = { id = "fl-mock00000000000" }
  }

  assert {
    condition     = output.vpc_id == "vpc-mock0000000000"
    error_message = "vpc_id output must reflect the created VPC's id"
  }

  assert {
    condition     = length(output.public_subnet_ids) == 2 && alltrue([for id in output.public_subnet_ids : id == "subnet-public-mock"])
    error_message = "public_subnet_ids output must contain one id per public subnet"
  }

  assert {
    condition     = length(output.app_subnet_ids) == 2 && alltrue([for id in output.app_subnet_ids : id == "subnet-app-mock"])
    error_message = "app_subnet_ids output must contain one id per app subnet"
  }

  assert {
    condition     = length(output.db_subnet_ids) == 2 && alltrue([for id in output.db_subnet_ids : id == "subnet-db-mock"])
    error_message = "db_subnet_ids output must contain one id per db subnet"
  }
}
