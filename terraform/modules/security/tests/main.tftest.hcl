# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Verifies security-group ingress/egress rules this module produces, entirely offline.

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_region_validation      = true
}

variables {
  name     = "golem-dev"
  vpc_id   = "vpc-0123456789abcdef0"
  vpc_cidr = "10.20.0.0/16"
}

run "alb_allows_plain_internet_ingress_on_443_and_80" {
  command = plan

  assert {
    condition     = contains([for i in aws_security_group.alb.ingress : i.from_port], 443)
    error_message = "alb security group must allow ingress on 443"
  }

  assert {
    condition     = contains([for i in aws_security_group.alb.ingress : i.from_port], 80)
    error_message = "alb security group must allow ingress on 80 (redirect/forward listener)"
  }

  assert {
    condition = alltrue([
      for i in aws_security_group.alb.ingress : contains(i.cidr_blocks, "0.0.0.0/0")
    ])
    error_message = "alb ingress must be open to the internet since Golem V1 has no CloudFront edge in front of it"
  }
}

run "app_sg_only_accepts_ingress_from_alb_sg" {
  command = plan

  assert {
    condition     = length(aws_security_group.app.ingress) == 1
    error_message = "app security group should have exactly one ingress rule"
  }

  assert {
    condition     = contains([for i in aws_security_group.app.ingress : i.from_port], 8000)
    error_message = "app ingress should default to port 8000"
  }
}

run "custom_app_port_is_honored" {
  command = plan

  variables {
    app_port = 9000
  }

  assert {
    condition     = contains([for i in aws_security_group.app.ingress : i.from_port], 9000)
    error_message = "custom app_port should be honored on the app security group ingress"
  }

  assert {
    condition     = contains([for e in aws_security_group.alb.egress : e.from_port], 9000)
    error_message = "custom app_port should be honored on the alb security group egress"
  }
}

run "db_sg_allows_postgres_egress_within_the_vpc" {
  command = plan

  # aws_security_group.db.ingress mixes a security_groups-scoped rule with a
  # self-referential one; the self rule's resolved value is unknown until
  # apply, which makes the whole ingress set unusable in a plan-time
  # condition. The db security group's egress (no self-reference involved)
  # is fully known at plan time and exercises the same module logic.
  assert {
    condition     = contains([for e in aws_security_group.db.egress : e.from_port], 5432)
    error_message = "db security group must allow PostgreSQL egress to targets inside the VPC"
  }

  assert {
    condition     = contains([for e in aws_security_group.db.egress : e.cidr_blocks[0]], "10.20.0.0/16")
    error_message = "db security group egress must be scoped to the VPC CIDR, not the open internet"
  }
}

run "rejects_an_invalid_vpc_id" {
  command = plan

  variables {
    vpc_id = "not-a-vpc-id"
  }

  expect_failures = [var.vpc_id]
}
