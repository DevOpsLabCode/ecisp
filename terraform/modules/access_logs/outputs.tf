# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Publishes the identifiers needed by ALB and CloudTrail S3 logging integrations.

output "bucket_id" {
  description = "S3 bucket name supplied to ALB and CloudTrail S3-server-access logging configurations."
  value       = aws_s3_bucket.this.id
}

output "bucket_arn" {
  description = "ARN of the centralized access-log bucket."
  value       = aws_s3_bucket.this.arn
}
