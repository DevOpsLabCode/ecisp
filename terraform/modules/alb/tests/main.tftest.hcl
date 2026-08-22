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
