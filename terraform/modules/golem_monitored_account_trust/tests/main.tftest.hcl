# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Verifies the trust policy, permission policy, and outputs this module produces, entirely offline. `aws_iam_policy_document` is always computed locally by the provider (never a real API call), so a blanket mock_provider -- which also mocks that computation into a placeholder -- breaks it; overriding only the one data source that genuinely needs a network call (aws_caller_identity) against a credential-free provider config keeps the real policy-document logic under test.

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_region_validation      = true
}

override_data {
  target = data.aws_caller_identity.current
  values = {
    account_id = "111111111111"
  }
}

run "creates_role_with_expected_name_and_defaults" {
  command = plan

  variables {
    trusted_principal_arn = "arn:aws:iam::222222222222:role/golem-iam-responder-execution"
    external_id           = "test-external-id"
  }

  assert {
    condition     = aws_iam_role.golem_iam_responder.name == "golem-iam-responder"
    error_message = "default role_name should be golem-iam-responder"
  }
}

run "permission_policy_scopes_to_monitored_prefix_in_this_account" {
  command = plan

  variables {
    trusted_principal_arn = "arn:aws:iam::222222222222:role/golem-iam-responder-execution"
    external_id           = "test-external-id"
  }

  assert {
    condition     = jsondecode(data.aws_iam_policy_document.permissions.json).Statement[0].Resource == "arn:aws:iam::111111111111:role/golem-monitored-*"
    error_message = "PutRolePolicy/DeleteRolePolicy must be scoped to this account's golem-monitored-* roles"
  }

  assert {
    condition     = [for s in jsondecode(data.aws_iam_policy_document.permissions.json).Statement : s.Sid][0] == "RevokeMonitoredWorkloadRoles"
    error_message = "expected the revoke statement first"
  }
}

run "trust_policy_names_only_the_configured_principal" {
  command = plan

  variables {
    trusted_principal_arn = "arn:aws:iam::222222222222:role/golem-iam-responder-execution"
    external_id           = "test-external-id"
  }

  assert {
    condition     = jsondecode(data.aws_iam_policy_document.assume.json).Statement[0].Principal.AWS == "arn:aws:iam::222222222222:role/golem-iam-responder-execution"
    error_message = "trust policy must name the exact trusted_principal_arn, not a whole account"
  }
}

run "external_id_condition_is_present_when_configured" {
  command = plan

  variables {
    trusted_principal_arn = "arn:aws:iam::222222222222:role/golem-iam-responder-execution"
    external_id           = "super-secret-external-id"
  }

  assert {
    condition     = jsondecode(data.aws_iam_policy_document.assume.json).Statement[0].Condition.StringEquals["sts:ExternalId"] == "super-secret-external-id"
    error_message = "external_id, when set, must appear as an ExternalId condition on the trust policy"
  }
}

run "external_id_condition_is_absent_when_not_configured" {
  command = plan

  variables {
    trusted_principal_arn = "arn:aws:iam::222222222222:role/golem-iam-responder-execution"
  }

  expect_failures = [check.external_id_recommended]

  assert {
    condition     = !can(jsondecode(data.aws_iam_policy_document.assume.json).Statement[0].Condition)
    error_message = "no Condition block should be present when external_id is left unset"
  }
}

run "custom_role_name_and_prefix_are_honored" {
  command = plan

  variables {
    trusted_principal_arn      = "arn:aws:iam::222222222222:role/golem-iam-responder-execution"
    external_id                = "test-external-id"
    role_name                  = "golem-iam-responder-custom"
    monitored_role_name_prefix = "golem-watched-"
  }

  assert {
    condition     = aws_iam_role.golem_iam_responder.name == "golem-iam-responder-custom"
    error_message = "custom role_name should be honored"
  }

  assert {
    condition     = jsondecode(data.aws_iam_policy_document.permissions.json).Statement[0].Resource == "arn:aws:iam::111111111111:role/golem-watched-*"
    error_message = "custom monitored_role_name_prefix should be reflected in the permission policy"
  }
}

run "rejects_a_trusted_principal_that_is_not_a_role_arn" {
  command = plan

  variables {
    trusted_principal_arn = "arn:aws:iam::222222222222:root"
    external_id           = "test-external-id"
  }

  expect_failures = [var.trusted_principal_arn]
}

run "rejects_a_role_name_with_invalid_characters" {
  command = plan

  variables {
    trusted_principal_arn = "arn:aws:iam::222222222222:role/golem-iam-responder-execution"
    external_id           = "test-external-id"
    role_name              = "bad role name!"
  }

  expect_failures = [var.role_name]
}

run "rejects_a_monitored_role_name_prefix_with_invalid_characters" {
  command = plan

  variables {
    trusted_principal_arn      = "arn:aws:iam::222222222222:role/golem-iam-responder-execution"
    external_id                = "test-external-id"
    monitored_role_name_prefix = "bad prefix!"
  }

  expect_failures = [var.monitored_role_name_prefix]
}

run "output_role_arn_and_role_name_reflect_the_created_role" {
  command = apply

  variables {
    trusted_principal_arn = "arn:aws:iam::222222222222:role/golem-iam-responder-execution"
    external_id           = "test-external-id"
  }

  override_resource {
    target = aws_iam_role.golem_iam_responder
    values = {
      arn  = "arn:aws:iam::111111111111:role/golem-iam-responder"
      name = "golem-iam-responder"
    }
  }

  override_resource {
    target = aws_iam_role_policy.golem_iam_responder
    values = {
      id = "golem-iam-responder:golem-iam-responder-permissions"
    }
  }

  assert {
    condition     = output.role_arn == "arn:aws:iam::111111111111:role/golem-iam-responder"
    error_message = "role_arn output must reflect the created role's ARN"
  }

  assert {
    condition     = output.role_name == "golem-iam-responder"
    error_message = "role_name output must reflect the created role's name"
  }
}
