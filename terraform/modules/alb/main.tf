# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Creates the internet-facing Application Load Balancer, listeners, access logging, and backend target group.
# Reading guide: Each listener represents one deliberate origin-security mode.
# Adapted from demand-gig-engine/terraform/modules/alb -- see terraform/README.md's ALB/certificate-arn decision.
# demand-gig-engine's original no-cert branch restricts HTTP access to requests carrying an X-Origin-Verify header,
# meant for CloudFront-origin traffic. Golem V1 has no CDN in front of this ALB, so that branch would make the ALB
# permanently unreachable (nothing would ever send that header). Golem's copy of this module replaces the no-cert
# branch with a plain HTTP listener that forwards unconditionally, and drops origin_verify_header_value entirely --
# see terraform/README.md for the full decision and its accepted risk (unauthenticated-at-the-load-balancer HTTP-only
# access when no certificate_arn is configured).

resource "aws_lb" "this" {
  #checkov:skip=CKV2_AWS_28:WAF is out of scope for Golem V1 (see terraform/README.md); a REGIONAL Web ACL association can be added at the root stack later without changing this module.
  #checkov:skip=CKV2_AWS_20:An HTTP-to-HTTPS redirect is created whenever a certificate is configured; the no-certificate path is a deliberate, documented V1 trial-only fallback (see terraform/README.md).
  name                       = substr(var.name, 0, 32)
  load_balancer_type         = "application"
  subnets                    = var.subnet_ids
  security_groups            = var.security_group_ids
  drop_invalid_header_fields = true
  desync_mitigation_mode     = "strictest"
  enable_deletion_protection = var.deletion_protection
  idle_timeout               = 60

  access_logs {
    bucket  = var.access_log_bucket_id
    prefix  = var.access_log_prefix
    enabled = true
  }

  tags = var.tags
}

resource "aws_lb_target_group" "backend" {
  #checkov:skip=CKV_AWS_378:ALB-to-ECS traffic remains inside private VPC subnets and security groups; viewer traffic is encrypted before reaching this internal hop whenever a certificate is configured.
  name        = substr("${var.name}-api", 0, 32)
  port        = var.target_port
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    path                = var.health_check_path
    matcher             = "200"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  deregistration_delay = 30
  tags                 = var.tags
}

# Redirect clear-text requests to TLS whenever a certificate is configured.
resource "aws_lb_listener" "http_redirect" {
  count             = var.certificate_arn == null ? 0 : 1
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# No certificate configured: forward HTTP directly, unconditionally. There is no CloudFront
# edge in front of Golem's ALB (unlike the vendored demand-gig-engine original this was
# adapted from), so gating this listener behind a header only CloudFront would ever send
# would make the ALB unreachable by design -- see this file's header comment.
resource "aws_lb_listener" "http_direct" {
  #checkov:skip=CKV_AWS_2:No-certificate mode is a documented V1 trial-only fallback with plain HTTP and no CloudFront edge; configure certificate_arn (see terraform/README.md) for anything beyond a quick trial.
  #checkov:skip=CKV_AWS_103:TLS 1.2 cannot be enforced on a listener that is deliberately plaintext HTTP; this listener only exists at all when var.certificate_arn is null.
  count             = var.certificate_arn == null ? 1 : 0
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.backend.arn
  }
}

resource "aws_lb_listener" "https" {
  count             = var.certificate_arn == null ? 0 : 1
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.backend.arn
  }
}
