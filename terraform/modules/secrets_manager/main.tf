# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Creates the encrypted application secret container and a stable initial secret version.
# Adapted from demand-gig-engine/terraform/modules/secrets_manager -- architecture (a single pre-seeded JSON secret,
# with `ignore_changes` on secret_string so an operator's later console/CLI rotation isn't clobbered by a future
# Terraform apply) is unchanged. Golem needs exactly one key here: IAM_RESPONDER_API_KEY, the fleet-wide bearer
# credential golem-iam-responder authenticates to golem-backend with (see iam-responder/app/backend_client.py and
# ui/backend/app/main.py's _authenticated_iam_component). A random initial value is generated so the secret is never
# created empty -- an operator can rotate it later without ever needing to know Terraform's generated value.

resource "random_password" "iam_responder_api_key" {
  length  = 48
  special = false
}

resource "aws_secretsmanager_secret" "golem" {
  #checkov:skip=CKV2_AWS_57:IAM_RESPONDER_API_KEY rotation is a coordinated golem-backend/golem-iam-responder redeploy, not an independent Lambda rotation.
  name                    = "${var.name}/golem-secrets"
  description             = "Fleet-wide credentials shared between golem-backend and golem-iam-responder"
  kms_key_id              = var.kms_key_arn
  recovery_window_in_days = var.recovery_window_in_days
  tags                    = var.tags
}

# Initializes or updates the JSON value stored in Secrets Manager.
resource "aws_secretsmanager_secret_version" "initial" {
  secret_id     = aws_secretsmanager_secret.golem.id
  secret_string = jsonencode({ IAM_RESPONDER_API_KEY = random_password.iam_responder_api_key.result })
  # Controls replacement, deletion protection, and drift behavior for this resource.
  lifecycle {
    ignore_changes = [secret_string]
  }
}
