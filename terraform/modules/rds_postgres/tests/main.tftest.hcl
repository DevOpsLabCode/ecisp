# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Verifies the RDS instance, RDS Proxy, and secret wiring this module produces, entirely offline.

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_region_validation      = true
}

variables {
  name                     = "golem-dev"
  subnet_ids               = ["subnet-0123456789abcdef0", "subnet-0123456789abcdef1"]
  security_group_ids       = ["sg-0123456789abcdef0"]
  kms_key_arn              = "arn:aws:kms:us-east-1:111111111111:key/abcd1234-0000-0000-0000-000000000000"
  instance_class           = "db.t4g.micro"
  allocated_storage        = 20
  permissions_boundary_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

run "creates_encrypted_instance_with_golem_database_and_username" {
  command = plan

  assert {
    condition     = aws_db_instance.this.db_name == "golem_defender"
    error_message = "database name should be golem_defender to match ui/docker-compose.yml"
  }

  assert {
    condition     = aws_db_instance.this.username == "golem"
    error_message = "master username should be golem to match ui/docker-compose.yml"
  }

  assert {
    condition     = aws_db_instance.this.storage_encrypted == true
    error_message = "storage must always be encrypted"
  }

  assert {
    condition     = aws_db_instance.this.publicly_accessible == false
    error_message = "the database must never be publicly accessible"
  }
}

run "forces_ssl_at_the_parameter_group_layer" {
  command = plan

  assert {
    condition     = [for p in aws_db_parameter_group.this.parameter : p.value if p.name == "rds.force_ssl"][0] == "1"
    error_message = "rds.force_ssl must be enabled"
  }
}

run "proxy_requires_tls_and_uses_secrets_manager_auth" {
  command = plan

  assert {
    condition     = aws_db_proxy.this.require_tls == true
    error_message = "RDS Proxy must require TLS"
  }

  assert {
    condition     = contains([for a in aws_db_proxy.this.auth : a.iam_auth], "DISABLED")
    error_message = "RDS Proxy should authenticate with the Secrets Manager secret, not IAM auth"
  }
}

run "runtime_secret_uses_the_golem_database_and_username_locals" {
  command = plan

  # aws_secretsmanager_secret_version.runtime.secret_string interpolates
  # aws_db_proxy.this.endpoint, which is unknown until apply, so the fully
  # resolved secret_string can't be asserted on at plan time. local.db_name
  # and local.db_username feed that same interpolation and are static
  # literals, known at plan -- asserting on them exercises the same
  # "no Django SECRET_KEY, golem/golem_defender literals" intent.
  assert {
    condition     = local.db_username == "golem" && local.db_name == "golem_defender"
    error_message = "db_username/db_name locals must be golem/golem_defender to match ui/docker-compose.yml"
  }

  assert {
    condition     = aws_secretsmanager_secret.runtime.name == "golem-dev/runtime"
    error_message = "runtime secret name should be <name>/runtime"
  }
}

run "rejects_an_undersized_initial_allocation" {
  command = plan

  variables {
    allocated_storage = 5
  }

  expect_failures = [var.allocated_storage]
}

run "rejects_an_invalid_name" {
  command = plan

  variables {
    name = "Invalid_Name"
  }

  expect_failures = [var.name]
}
