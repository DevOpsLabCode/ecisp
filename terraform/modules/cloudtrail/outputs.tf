# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Publishes CloudTrail identifiers for audit and monitoring integrations.

output "trail_arn" {
  description = "CloudTrail trail ARN."
  value       = aws_cloudtrail.this.arn
}

output "log_bucket_id" {
  description = "S3 bucket name storing CloudTrail's own delivered log objects."
  value       = aws_s3_bucket.logs.id
}

output "sns_topic_arn" {
  description = "Encrypted SNS topic CloudTrail publishes delivery notifications to."
  value       = aws_sns_topic.notifications.arn
}
