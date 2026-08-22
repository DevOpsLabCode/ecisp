# Author: Stan Zvenigorodskiy | DevOps Lab Inc. | https://DevOpsLabInc.com
# Purpose: Publishes operational alerting and dashboard identifiers.

output "alarm_topic_arn" {
  description = "Encrypted SNS topic receiving alarm and recovery notifications."
  value       = aws_sns_topic.alerts.arn
}

output "dashboard_name" {
  description = "CloudWatch service dashboard name."
  value       = aws_cloudwatch_dashboard.service.dashboard_name
}
