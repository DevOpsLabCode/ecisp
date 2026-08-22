# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Publishes reusable values produced by the golem_iam_responder_execution Terraform module.
# Reading guide: Each comment explains why the following Terraform block exists.

# Output `policy_arn`: attach this to whatever IAM role iam-responder
# actually runs under -- an aws_iam_role_policy_attachment (or the
# equivalent for the compute platform in use) in the composition that
# deploys iam-responder itself.
output "policy_arn" {
  description = "ARN of the policy granting sts:AssumeRole into every monitored account's golem-iam-responder role."
  value       = aws_iam_policy.assume_monitored_accounts.arn
}
