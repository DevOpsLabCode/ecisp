# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Verifies listener wiring for both the certificate and no-certificate branches this module produces, entirely offline.

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_region_validation      = true
}

variables {
  name                 = "golem-dev"
  vpc_id               = "vpc-0123456789abcdef0"
  subnet_ids           = ["subnet-0123456789abcdef0", "subnet-0123456789abcdef1"]
  security_group_ids   = ["sg-0123456789abcdef0"]
  access_log_bucket_id = "golem-dev-111111111111-access-logs"
}

run "no_certificate_forwards_http_directly_without_a_header_gate" {
  command = plan

  assert {
    condition     = length(aws_lb_listener.http_direct) == 1
    error_message = "no certificate_arn should create the unconditional HTTP forwarding listener"
  }

  assert {
    condition     = aws_lb_listener.http_direct[0].default_action[0].type == "forward"
    error_message = "the no-certificate listener must forward directly, not require a header"
  }

  assert {
    condition     = length(aws_lb_listener.https) == 0
    error_message = "no certificate_arn should create no HTTPS listener"
  }

  assert {
    condition     = length(aws_lb_listener.http_redirect) == 0
    error_message = "no certificate_arn should create no HTTP-to-HTTPS redirect listener"
  }
}

run "certificate_configured_creates_https_listener_and_redirect" {
  command = plan

  variables {
    certificate_arn = "arn:aws:acm:us-east-1:111111111111:certificate/abcd1234-0000-0000-0000-000000000000"
  }

  assert {
    condition     = length(aws_lb_listener.https) == 1
    error_message = "certificate_arn should create the HTTPS listener"
  }

  assert {
    condition     = aws_lb_listener.https[0].certificate_arn == "arn:aws:acm:us-east-1:111111111111:certificate/abcd1234-0000-0000-0000-000000000000"
    error_message = "HTTPS listener must use the supplied certificate_arn"
  }

  assert {
    condition     = length(aws_lb_listener.http_redirect) == 1
    error_message = "certificate_arn should create the HTTP-to-HTTPS redirect listener"
  }

  assert {
    condition     = aws_lb_listener.http_redirect[0].default_action[0].type == "redirect"
    error_message = "the redirect listener's default action must be a redirect"
  }

  assert {
    condition     = length(aws_lb_listener.http_direct) == 0
    error_message = "certificate_arn should create no unconditional HTTP-forwarding listener"
  }
}

run "target_group_defaults_match_golem_backends_health_endpoint" {
  command = plan

  assert {
    condition     = aws_lb_target_group.backend.port == 8000
    error_message = "default target_port should be 8000"
  }

  assert {
    condition     = aws_lb_target_group.backend.health_check[0].path == "/api/health"
    error_message = "default health_check_path should be /api/health"
  }
}

run "rejects_an_invalid_certificate_arn" {
  command = plan

  variables {
    certificate_arn = "not-an-arn"
  }

  expect_failures = [var.certificate_arn]
}

run "rejects_a_name_that_is_too_short" {
  command = plan

  variables {
    name = "ab"
  }

  expect_failures = [var.name]
}

run "rejects_an_invalid_vpc_id" {
  command = plan

  variables {
    vpc_id = "not-a-vpc-id"
  }

  expect_failures = [var.vpc_id]
}

run "rejects_fewer_than_two_subnet_ids" {
  command = plan

  variables {
    subnet_ids = ["subnet-0123456789abcdef0"]
  }

  expect_failures = [var.subnet_ids]
}

run "rejects_an_empty_security_group_id_list" {
  command = plan

  variables {
    security_group_ids = []
  }

  expect_failures = [var.security_group_ids]
}

run "rejects_an_out_of_range_target_port" {
  command = plan

  variables {
    target_port = 70000
  }

  expect_failures = [var.target_port]
}

run "rejects_a_health_check_path_without_a_leading_slash" {
  command = plan

  variables {
    health_check_path = "api/health"
  }

  expect_failures = [var.health_check_path]
}

run "rejects_an_empty_access_log_bucket_id" {
  command = plan

  variables {
    access_log_bucket_id = "ab"
  }

  expect_failures = [var.access_log_bucket_id]
}

run "custom_access_log_prefix_is_honored" {
  command = plan

  variables {
    access_log_prefix = "custom-alb-prefix"
  }

  assert {
    condition     = aws_lb.this.access_logs[0].prefix == "custom-alb-prefix"
    error_message = "custom access_log_prefix should be honored on the ALB access_logs block"
  }
}

run "rejects_an_access_log_prefix_starting_with_a_slash" {
  command = plan

  variables {
    access_log_prefix = "/alb"
  }

  expect_failures = [var.access_log_prefix]
}

run "output_values_reflect_the_created_load_balancer_and_target_group" {
  command = apply

  override_resource {
    target = aws_lb.this
    values = {
      arn      = "arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/app/golem-dev/abc123"
      dns_name = "golem-dev-123456789.us-east-1.elb.amazonaws.com"
      zone_id  = "Z35SXDOTRQ7X7K"
    }
  }

  override_resource {
    target = aws_lb_target_group.backend
    values = {
      arn        = "arn:aws:elasticloadbalancing:us-east-1:111111111111:targetgroup/golem-dev-api/def456"
      arn_suffix = "targetgroup/golem-dev-api/def456"
    }
  }

  override_resource {
    target = aws_lb_listener.http_direct
    values = {
      arn = "arn:aws:elasticloadbalancing:us-east-1:111111111111:listener/app/golem-dev/abc123/http"
    }
  }

  assert {
    condition     = output.arn == "arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/app/golem-dev/abc123"
    error_message = "arn output must reflect the created load balancer's ARN"
  }

  assert {
    condition     = output.dns_name == "golem-dev-123456789.us-east-1.elb.amazonaws.com"
    error_message = "dns_name output must reflect the created load balancer's DNS name"
  }

  assert {
    condition     = output.zone_id == "Z35SXDOTRQ7X7K"
    error_message = "zone_id output must reflect the created load balancer's hosted-zone id"
  }

  assert {
    condition     = output.target_group_arn == "arn:aws:elasticloadbalancing:us-east-1:111111111111:targetgroup/golem-dev-api/def456"
    error_message = "target_group_arn output must reflect the created target group's ARN"
  }

  assert {
    condition     = output.target_group_arn_suffix == "targetgroup/golem-dev-api/def456"
    error_message = "target_group_arn_suffix output must reflect the created target group's ARN suffix"
  }
}
