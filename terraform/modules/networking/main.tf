# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Builds isolated subnet tiers, resilient routing, encrypted VPC flow logs, and private S3 access.
# Vendored from demand-gig-engine/terraform/modules/networking with no logic changes -- see terraform/README.md for the vendoring rationale.

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_region" "current" {}


locals {
  azs = slice(data.aws_availability_zones.available.names, 0, var.az_count)

  # Resource instance keys must be known during planning. Use static numeric
  # keys derived only from the input az_count; Availability Zone names remain
  # values and may be resolved during the plan.
  az_indices = {
    for index in range(var.az_count) : tostring(index) => index
  }

  nat_gateway_indices = var.nat_gateway_per_az ? local.az_indices : {
    "0" = 0
  }
}

resource "aws_vpc" "this" {
  cidr_block           = var.cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = merge(var.tags, { Name = "${var.name}-vpc" })
}

# Remove all rules from the default security group so workloads must use the explicit groups in the security module.
resource "aws_default_security_group" "this" {
  vpc_id = aws_vpc.this.id
  tags   = merge(var.tags, { Name = "${var.name}-default-deny" })
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = merge(var.tags, { Name = "${var.name}-igw" })
}

resource "aws_subnet" "public" {
  for_each = local.az_indices

  vpc_id                  = aws_vpc.this.id
  availability_zone       = local.azs[each.value]
  cidr_block              = cidrsubnet(var.cidr, 4, each.value)
  map_public_ip_on_launch = false
  tags                    = merge(var.tags, { Name = "${var.name}-public-${local.azs[each.value]}", Tier = "public" })
}

resource "aws_subnet" "app" {
  for_each = local.az_indices

  vpc_id            = aws_vpc.this.id
  availability_zone = local.azs[each.value]
  cidr_block        = cidrsubnet(var.cidr, 4, each.value + 4)
  tags              = merge(var.tags, { Name = "${var.name}-app-${local.azs[each.value]}", Tier = "private-app" })
}

resource "aws_subnet" "db" {
  for_each = local.az_indices

  vpc_id            = aws_vpc.this.id
  availability_zone = local.azs[each.value]
  cidr_block        = cidrsubnet(var.cidr, 4, each.value + 8)
  tags              = merge(var.tags, { Name = "${var.name}-db-${local.azs[each.value]}", Tier = "private-db" })
}

resource "aws_eip" "nat" {
  for_each = local.nat_gateway_indices
  domain   = "vpc"
  tags     = var.tags
}

resource "aws_nat_gateway" "this" {
  for_each      = local.nat_gateway_indices
  allocation_id = aws_eip.nat[each.key].id
  subnet_id     = aws_subnet.public[each.key].id
  depends_on    = [aws_internet_gateway.this]
  tags          = var.tags
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }

  tags = var.tags
}

resource "aws_route_table_association" "public" {
  for_each       = local.az_indices
  subnet_id      = aws_subnet.public[each.key].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "app" {
  for_each = local.az_indices
  vpc_id   = aws_vpc.this.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.this[var.nat_gateway_per_az ? each.key : "0"].id
  }

  tags = var.tags
}

resource "aws_route_table_association" "app" {
  for_each       = local.az_indices
  subnet_id      = aws_subnet.app[each.key].id
  route_table_id = aws_route_table.app[each.key].id
}

resource "aws_route_table" "db" {
  vpc_id = aws_vpc.this.id
  tags   = var.tags
}

resource "aws_route_table_association" "db" {
  for_each       = local.az_indices
  subnet_id      = aws_subnet.db[each.key].id
  route_table_id = aws_route_table.db.id
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${data.aws_region.current.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = concat([for table in aws_route_table.app : table.id], [aws_route_table.db.id])
  tags              = var.tags
}

# Store all accepted, rejected, and aggregate network-flow metadata for at least one year.
resource "aws_cloudwatch_log_group" "flow" {
  name              = "/aws/vpc/${var.name}/flow-logs"
  retention_in_days = var.flow_log_retention_days
  kms_key_id        = var.kms_key_arn
  tags              = var.tags
}

data "aws_iam_policy_document" "flow_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "flow" {
  permissions_boundary = var.permissions_boundary_arn
  name                 = "${var.name}-vpc-flow-logs"
  assume_role_policy   = data.aws_iam_policy_document.flow_assume.json
  tags                 = var.tags
}

resource "aws_iam_role_policy" "flow" {
  role = aws_iam_role.flow.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams",
          "logs:PutLogEvents",
        ]
        Resource = [aws_cloudwatch_log_group.flow.arn, "${aws_cloudwatch_log_group.flow.arn}:*"]
      }
    ]
  })
}

resource "aws_flow_log" "this" {
  iam_role_arn    = aws_iam_role.flow.arn
  log_destination = aws_cloudwatch_log_group.flow.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.this.id

  tags = var.tags
}
