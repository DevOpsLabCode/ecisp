# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Publishes reusable values produced by the kms Terraform module.

# Output `key_arn`: ARN of the key resource consumed by this module.
output "key_arn" {
  value = aws_kms_key.this.arn
}
# Output `key_id`: Identifier of the key resource consumed by this module.
output "key_id" {
  value = aws_kms_key.this.key_id
}
