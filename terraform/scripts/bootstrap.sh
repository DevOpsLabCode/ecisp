#!/usr/bin/env bash
# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Provisions or verifies a KMS-encrypted Terraform backend through the dedicated global/bootstrap Terraform root.
# Execution model: fail closed, bootstrap locally only for the first run, then migrate state into the protected S3 backend.
# Adapted from demand-gig-engine/scripts/bootstrap.sh with no logic changes beyond PROJECT_NAME's default -- see
# terraform/README.md and terraform/global/bootstrap/README.md for the full local-state-then-migrate explanation.
# NOTE: this script has been read and reasoned through carefully but has NOT been executed against a real AWS
# account as part of this work -- see terraform/README.md's honest unverified-without-real-AWS statement.

set -Eeuo pipefail

ENVIRONMENT="${1:-dev}"
[[ "$ENVIRONMENT" =~ ^(account|dev|prod)$ ]] || {
  echo "Usage: $0 account|dev|prod" >&2
  exit 2
}

for command_name in aws terraform; do
  command -v "$command_name" >/dev/null || {
    echo "$command_name is required" >&2
    exit 1
  }
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BOOTSTRAP_DIR="$ROOT/global/bootstrap"
REGION="${AWS_REGION:-us-east-1}"
PROJECT_NAME="${PROJECT_NAME:-golem}"
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
BUCKET="${PROJECT_NAME}-${ENVIRONMENT}-${ACCOUNT_ID}-tfstate"
KMS_ALIAS="alias/${PROJECT_NAME}-${ENVIRONMENT}-tfstate"
CREATE_BACKEND="${CREATE_BACKEND:-true}"

BOOTSTRAP_BACKEND_FILE="$BOOTSTRAP_DIR/backend-${ENVIRONMENT}.hcl"

if [[ "$ENVIRONMENT" == "account" ]]; then
  CONSUMER_BACKEND_FILE="$ROOT/global/account/backend.hcl"
  CONSUMER_STATE_KEY="account-foundation/terraform.tfstate"
else
  CONSUMER_BACKEND_FILE="$ROOT/envs/$ENVIRONMENT/backend.hcl"
  CONSUMER_STATE_KEY="$ENVIRONMENT/terraform.tfstate"
fi

write_backend_file() {
  local destination="$1"
  local key="$2"
  local kms_key_arn="$3"

  mkdir -p "$(dirname "$destination")"

  cat >"$destination" <<EOF_BACKEND
bucket       = "$BUCKET"
key          = "$key"
region       = "$REGION"
encrypt      = true
kms_key_id   = "$kms_key_arn"
use_lockfile = true
EOF_BACKEND
}

verify_backend_controls() {
  local versioning encryption

  versioning="$(
    aws s3api get-bucket-versioning \
      --bucket "$BUCKET" \
      --query Status \
      --output text
  )"

  [[ "$versioning" == "Enabled" ]] || {
    echo "Terraform state bucket $BUCKET does not have versioning enabled." >&2
    exit 1
  }

  aws s3api get-public-access-block --bucket "$BUCKET" >/dev/null

  encryption="$(
    aws s3api get-bucket-encryption \
      --bucket "$BUCKET" \
      --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' \
      --output text
  )"

  [[ "$encryption" == "aws:kms" ]] || {
    echo "Terraform state bucket $BUCKET must use aws:kms default encryption." >&2
    exit 1
  }
}

bootstrap_locally_then_migrate() {
  local versions_file versions_backup

  versions_file="$BOOTSTRAP_DIR/versions.tf"
  versions_backup="$(mktemp)"
  cp "$versions_file" "$versions_backup"

  restore_backend_declaration() {
    if [[ -f "$versions_backup" ]]; then
      cp "$versions_backup" "$versions_file"
      rm -f "$versions_backup"
    fi
  }

  # Always restore the committed S3 backend declaration if local bootstrap
  # initialization or apply fails.
  trap restore_backend_declaration EXIT INT TERM

  # The real bootstrap root declares an S3 backend. On the first run that
  # bucket does not exist yet, so temporarily remove only that backend block
  # while Terraform creates the protected bucket and KMS key using local state.
  sed -i '/^[[:space:]]*backend[[:space:]]*"s3"[[:space:]]*{[[:space:]]*}[[:space:]]*$/d' \
    "$versions_file"

  rm -rf "$BOOTSTRAP_DIR/.terraform"

  terraform -chdir="$BOOTSTRAP_DIR" init -backend=false -input=false >&2
  terraform -chdir="$BOOTSTRAP_DIR" apply \
    -auto-approve \
    -input=false \
    -var="aws_region=$REGION" \
    -var="environment=$ENVIRONMENT" \
    -var="project_name=$PROJECT_NAME" >&2

  KMS_KEY_ARN="$(
    terraform -chdir="$BOOTSTRAP_DIR" output -raw kms_key_arn
  )"

  write_backend_file \
    "$BOOTSTRAP_BACKEND_FILE" \
    "bootstrap/$ENVIRONMENT/terraform.tfstate" \
    "$KMS_KEY_ARN"

  # Restore the S3 backend declaration before migrating the newly created
  # local state into the protected bucket.
  restore_backend_declaration
  trap - EXIT INT TERM
  rm -rf "$BOOTSTRAP_DIR/.terraform"

  terraform -chdir="$BOOTSTRAP_DIR" init \
    -force-copy \
    -migrate-state \
    -input=false \
    -backend-config="$BOOTSTRAP_BACKEND_FILE" >&2

  rm -f \
    "$BOOTSTRAP_DIR/terraform.tfstate" \
    "$BOOTSTRAP_DIR/terraform.tfstate.backup"
}

if ! aws s3api head-bucket --bucket "$BUCKET" >/dev/null 2>&1; then
  if [[ "$CREATE_BACKEND" != "true" ]]; then
    echo "Terraform state bucket $BUCKET does not exist. Run bootstrap.sh once with trusted credentials and CREATE_BACKEND=true." >&2
    exit 1
  fi

  echo "Provisioning protected Terraform backend $BUCKET through global/bootstrap" >&2
  bootstrap_locally_then_migrate
else
  verify_backend_controls

  KMS_KEY_ARN="$(
    aws kms describe-key \
      --key-id "$KMS_ALIAS" \
      --query KeyMetadata.Arn \
      --output text
  )"

  [[ "$KMS_KEY_ARN" == arn:*:kms:*:*:key/* ]] || {
    echo "Unable to resolve protected state key $KMS_ALIAS." >&2
    exit 1
  }

  write_backend_file \
    "$BOOTSTRAP_BACKEND_FILE" \
    "bootstrap/$ENVIRONMENT/terraform.tfstate" \
    "$KMS_KEY_ARN"

  if [[ "$CREATE_BACKEND" == "true" ]]; then
    rm -rf "$BOOTSTRAP_DIR/.terraform"

    terraform -chdir="$BOOTSTRAP_DIR" init \
      -reconfigure \
      -input=false \
      -backend-config="$BOOTSTRAP_BACKEND_FILE" >&2

    if [[ -z "$(terraform -chdir="$BOOTSTRAP_DIR" state list 2>/dev/null)" ]]; then
      echo "Backend bucket exists but bootstrap Terraform state is missing. Import the existing bootstrap resources before continuing; refusing to create a second ownership path." >&2
      exit 1
    fi

    terraform -chdir="$BOOTSTRAP_DIR" apply \
      -auto-approve \
      -input=false \
      -var="aws_region=$REGION" \
      -var="environment=$ENVIRONMENT" \
      -var="project_name=$PROJECT_NAME" >&2
  fi
fi

verify_backend_controls

write_backend_file \
  "$CONSUMER_BACKEND_FILE" \
  "$CONSUMER_STATE_KEY" \
  "$KMS_KEY_ARN"

# Output contract: stdout contains exactly one value, the generated consumer
# backend configuration path. All diagnostics and Terraform progress are sent
# to stderr so callers may safely use command substitution.
printf '%s\n' "$CONSUMER_BACKEND_FILE"
