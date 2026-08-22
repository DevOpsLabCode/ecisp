# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Defines least-privilege security groups for the ALB, ECS tasks, and PostgreSQL.
# Reading guide: Ingress identifies who may initiate a connection; egress limits each tier to the ports it actually uses.
# Adapted from demand-gig-engine/terraform/modules/security -- Golem V1 has no CloudFront in front of the ALB (see
# terraform/README.md's ALB/certificate decision) and no cache layer, so this module diverges from the vendored
# original in two ways: the alb security group allows plain internet ingress instead of only the AWS-managed
# CloudFront origin-facing prefix list, and there is no redis security group at all.

resource "aws_security_group" "alb" {
  #checkov:skip=CKV2_AWS_5:The ALB security group is attached by module.alb through security_group_ids; the attachment crosses the reusable module boundary.
  #checkov:skip=CKV_AWS_260:Golem V1 has no CloudFront edge in front of this ALB (see terraform/README.md), so plain internet ingress on 80 is the deliberate, documented alternative rather than an unreachable CloudFront-only prefix list; 80 exists only to redirect to 443 or, with no certificate configured, to forward directly (see modules/alb).
  name_prefix = "${var.name}-alb-"
  description = "Allow internet ingress to the public ALB; Golem V1 has no CloudFront edge in front of it"
  vpc_id      = var.vpc_id

  # No CloudFront edge exists in front of this ALB (see terraform/README.md), so the
  # only useful restriction left is the protocol/port itself, not a managed prefix list.
  ingress {
    description = "HTTPS from the internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Only opened when a certificate is configured, so the http-to-https redirect
  # listener has somewhere to receive plaintext requests to redirect (see
  # modules/alb). When no certificate is configured, the ALB has no HTTPS
  # listener either, so port 80 forwards directly instead of redirecting.
  ingress {
    description = "HTTP from the internet (redirected to HTTPS when a certificate is configured, forwarded directly otherwise)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # The ALB initiates only application-port connections to targets inside this VPC.
  egress {
    description = "Application-port traffic to private ECS targets"
    from_port   = var.app_port
    to_port     = var.app_port
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = merge(var.tags, { Name = "${var.name}-alb" })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "app" {
  #checkov:skip=CKV2_AWS_5:The application security group is attached to ECS task ENIs by the backend and iam-responder service modules.
  name_prefix = "${var.name}-app-"
  description = "Application tasks reachable only from the ALB"
  vpc_id      = var.vpc_id

  ingress {
    description     = "Backend API traffic from ALB"
    from_port       = var.app_port
    to_port         = var.app_port
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  # External provider APIs (AWS STS AssumeRole into monitored accounts, the
  # Golem backend's own outbound calls), AWS public endpoints, and
  # package-independent HTTPS calls.
  egress {
    description = "HTTPS to approved internet and AWS service endpoints through NAT"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "PostgreSQL through RDS Proxy in private database subnets"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  # Route 53 Resolver is reached inside the VPC; both transports are allowed
  # because DNS can fall back from UDP to TCP for larger responses.
  egress {
    description = "DNS over UDP to the VPC resolver"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "DNS over TCP to the VPC resolver"
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = merge(var.tags, { Name = "${var.name}-app" })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "db" {
  #checkov:skip=CKV2_AWS_5:The database security group is attached to the RDS instance and RDS Proxy through the database module input.
  name_prefix = "${var.name}-db-"
  description = "PostgreSQL and RDS Proxy access from application tasks"
  vpc_id      = var.vpc_id

  ingress {
    description     = "PostgreSQL from application tasks"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }

  # RDS Proxy and the database share this group, so proxy-to-database traffic
  # must be permitted between members of the same security group.
  ingress {
    description = "RDS Proxy to PostgreSQL"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    self        = true
  }

  egress {
    description = "RDS Proxy connection to PostgreSQL targets inside the VPC"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = merge(var.tags, { Name = "${var.name}-db" })

  lifecycle {
    create_before_destroy = true
  }
}
